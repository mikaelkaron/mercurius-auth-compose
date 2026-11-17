import Fastify, { type FastifyInstance, type FastifyPluginAsync } from 'fastify'
import type { ValueNode } from 'graphql'
import mercurius, { type MercuriusContext } from 'mercurius'
import mercuriusAuth, { type MercuriusAuthOptions } from 'mercurius-auth'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { INVALID_OPTS_CODE, INVALID_POLICY_CODE } from '../src/errors.ts'
import {
  composedDirectiveSdl,
  createDirectiveAuth,
  createExternalAuth,
  UNAUTHORIZED_CODE,
  type ComposedPolicy
} from '../src/mercurius.ts'

// A self-contained check for the tests: a required `scope`, judged against the
// caller's held scopes (sent as a comma-separated `x-scopes` header). This
// stands in for any real check the composer knows nothing about.
interface ScopeCheck {
  scope: string
}

const held = (context: MercuriusContext): string[] => {
  const raw = context.reply.request.headers['x-scopes']
  return (typeof raw === 'string' ? raw : '').split(',').filter(Boolean)
}

const parseScope = (node: ValueNode): ScopeCheck => {
  if (node.kind !== 'ObjectValue') throw new Error('each check must be an object')
  const field = node.fields.find((f) => f.name.value === 'scope')
  if (field?.value.kind !== 'StringValue' || field.value.value === '') {
    throw new Error('each check needs a non-empty `scope` string')
  }
  return { scope: field.value.value }
}

const evaluate = (check: ScopeCheck, scopes: string[]): boolean => scopes.includes(check.scope)

const apps: FastifyInstance[] = []
const register = (app: FastifyInstance, opts: MercuriusAuthOptions) =>
  app.register(mercuriusAuth as unknown as FastifyPluginAsync<MercuriusAuthOptions>, opts)

const query = (app: FastifyInstance, q: string, headers: Record<string, string> = {}) =>
  app
    .inject({ method: 'POST', url: '/graphql', headers, payload: { query: q } })
    .then(
      (res) =>
        res.json() as {
          data?: Record<string, unknown>
          errors?: { message: string; extensions?: { code?: string } }[]
        }
    )

afterEach(async () => {
  await Promise.all(apps.splice(0).map((a) => a.close()))
})

describe('composedDirectiveSdl', () => {
  it('names the shared types after the directive so several can coexist', () => {
    const auth = composedDirectiveSdl('auth')
    expect(auth).toMatch(/enum AuthRelation \{\s+AND\s+OR\s+\}/)
    expect(auth).toContain('input AuthCheck {')
    expect(auth).toMatch(
      /directive @auth\(\s+checks: \[AuthCheck!\]!\s+relation: AuthRelation\s+\) repeatable on OBJECT \| FIELD_DEFINITION/
    )

    const guard = composedDirectiveSdl('guard')
    expect(guard).toMatch(/enum GuardRelation \{/)
    expect(guard).toContain('directive @guard(')
  })

  it('embeds the caller-supplied check-input body', () => {
    expect(composedDirectiveSdl('auth')).toContain('targets: [String!]!') // default
    expect(composedDirectiveSdl('auth', 'scope: String!')).toContain('scope: String!')
  })
})

describe('createDirectiveAuth', () => {
  const build = async (opts: Partial<Parameters<typeof createDirectiveAuth<ScopeCheck, string[]>>[0]> = {}) => {
    const app = Fastify({ logger: false })
    const { applyPolicy, sdl, directive } = createDirectiveAuth<ScopeCheck, string[]>({
      checkInput: 'scope: String!',
      parseCheck: parseScope,
      prepare: held,
      evaluate,
      ...opts
    })
    await app.register(mercurius, {
      schema: `
        ${sdl}
        type Query { health: Boolean }
        type Mutation {
          orAny: Boolean @auth(checks: [{ scope: "a" }, { scope: "b" }], relation: OR)
          andAll: Boolean @auth(checks: [{ scope: "a" }, { scope: "b" }], relation: AND)
          defaulted: Boolean @auth(checks: [{ scope: "a" }, { scope: "b" }])
          none: Boolean @auth(checks: [])
          bad: Boolean @auth(checks: [{ scope: "" }])
          single: Boolean @auth(checks: { scope: "a" })
          nulled: Boolean @auth(checks: [{ scope: "a" }, { scope: "b" }], relation: null)
          both: Boolean @auth(checks: [{ scope: "a" }]) @auth(checks: [{ scope: "b" }])
        }
      `,
      resolvers: {
        Mutation: {
          orAny: () => true,
          andAll: () => true,
          defaulted: () => true,
          none: () => true,
          bad: () => true,
          single: () => true,
          nulled: () => true,
          both: () => true
        }
      },
      graphiql: false
    })
    await register(app, { mode: 'directive', authDirective: directive, applyPolicy })
    await app.ready()
    apps.push(app)
    return app
  }

  it('OR grants when any check passes, denies when none do', async () => {
    const app = await build()
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'b' })).data?.orAny).toBe(true)
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'z' })).errors).toBeTruthy()
  })

  it('the default denial surfaces a coded, mercurius-shaped error (extensions.code)', async () => {
    const app = await build() // no onDeny → defaultDeny
    const res = await query(app, 'mutation { orAny }', { 'x-scopes': 'z' })
    expect(res.errors?.[0]?.message).toBe('Unauthorized')
    expect(res.errors?.[0]?.extensions?.code).toBe(UNAUTHORIZED_CODE)
  })

  it('AND requires every check', async () => {
    const app = await build()
    expect((await query(app, 'mutation { andAll }', { 'x-scopes': 'a,b' })).data?.andAll).toBe(true)
    expect((await query(app, 'mutation { andAll }', { 'x-scopes': 'a' })).errors).toBeTruthy()
  })

  it('defaults an omitted relation to OR', async () => {
    const app = await build()
    expect((await query(app, 'mutation { defaulted }', { 'x-scopes': 'a' })).data?.defaulted).toBe(true)
  })

  it('defaultRelation governs a field with no explicit relation', async () => {
    const app = await build({ defaultRelation: 'and' })
    expect((await query(app, 'mutation { defaulted }', { 'x-scopes': 'a' })).errors).toBeTruthy()
    expect((await query(app, 'mutation { defaulted }', { 'x-scopes': 'a,b' })).data?.defaulted).toBe(true)
  })

  it('an empty checks list denies', async () => {
    const app = await build()
    expect((await query(app, 'mutation { none }', { 'x-scopes': 'a,b' })).errors).toBeTruthy()
  })

  it('a malformed check (parseCheck throws) is a policy error', async () => {
    const app = await build()
    expect((await query(app, 'mutation { bad }', { 'x-scopes': 'a' })).errors?.[0]?.message).toMatch(
      /non-empty `scope`/
    )
  })

  it('reads a single check object as a list of one', async () => {
    const app = await build()
    expect((await query(app, 'mutation { single }', { 'x-scopes': 'a' })).data?.single).toBe(true)
    expect((await query(app, 'mutation { single }', { 'x-scopes': 'b' })).errors).toBeTruthy()
  })

  it('treats relation: null like an absent relation', async () => {
    const app = await build({ defaultRelation: 'and' })
    expect((await query(app, 'mutation { nulled }', { 'x-scopes': 'a' })).errors).toBeTruthy()
    expect((await query(app, 'mutation { nulled }', { 'x-scopes': 'a,b' })).data?.nulled).toBe(true)
  })

  it('ANDs a repeated directive: each occurrence is enforced', async () => {
    const app = await build()
    expect((await query(app, 'mutation { both }', { 'x-scopes': 'a' })).errors).toBeTruthy()
    expect((await query(app, 'mutation { both }', { 'x-scopes': 'a,b' })).data?.both).toBe(true)
  })

  it('runs prepare once per request, however many protected fields it resolves', async () => {
    const prepare = vi.fn(held)
    const app = await build({ prepare })
    const res = await query(app, 'mutation { orAny andAll defaulted }', { 'x-scopes': 'a,b' })
    expect(res.data).toEqual({ orAny: true, andAll: true, defaulted: true })
    expect(prepare).toHaveBeenCalledOnce()
    await query(app, 'mutation { orAny }', { 'x-scopes': 'a' })
    expect(prepare).toHaveBeenCalledTimes(2)
  })

  it("stops at the deciding check by default, and runs every one with run: 'all'", async () => {
    const first = vi.fn(evaluate)
    const app = await build({ evaluate: first })
    await query(app, 'mutation { orAny }', { 'x-scopes': 'a,b' })
    expect(first).toHaveBeenCalledOnce()

    const all = vi.fn(evaluate)
    const app2 = await build({ evaluate: all, run: 'all' })
    await query(app2, 'mutation { orAny }', { 'x-scopes': 'a,b' })
    expect(all).toHaveBeenCalledTimes(2)
  })

  it('a throwing check does not deny a field another check grants under OR', async () => {
    const app = await build({
      evaluate: (check, scopes) => {
        if (check.scope === 'a') throw new Error('check a unavailable')
        return scopes.includes(check.scope)
      }
    })
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'b' })).data?.orAny).toBe(true)
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'z' })).errors?.[0]?.message).toBe(
      'check a unavailable'
    )
  })

  it('awaits onDeny and passes it the context and resolve info', async () => {
    const onDeny = vi.fn(async (_context: MercuriusContext, info: { fieldName: string }) =>
      new Error(`no ${info.fieldName}`)
    )
    const app = await build({ onDeny })
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'z' })).errors?.[0]?.message).toBe('no orAny')
    expect(onDeny).toHaveBeenCalledOnce()
  })

  it('an onDeny that returns no Error denies with a coded invalid-policy error', async () => {
    const app = await build({ onDeny: (() => 'nope') as never })
    const res = await query(app, 'mutation { orAny }', { 'x-scopes': 'z' })
    expect(res.data?.orAny ?? null).toBeNull()
    expect(res.errors?.[0]?.message).toBe('Invalid auth policy on orAny: onDeny must return an Error')
  })

  it('a non-Error thrown by prepare denies with a coded invalid-policy error', async () => {
    const app = await build({
      prepare: () => {
        throw 'down' // eslint-disable-line no-throw-literal
      }
    })
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'a' })).errors?.[0]?.message).toBe(
      'Invalid auth policy on orAny: down'
    )
  })

  it('a throwing prepare denies with its own error, distinct from onDeny', async () => {
    const app = await build({
      prepare: () => {
        throw new Error('identity unavailable')
      },
      onDeny: () => new Error('untrusted')
    })
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'a' })).errors?.[0]?.message).toBe(
      'identity unavailable'
    )
  })
})

describe('createExternalAuth', () => {
  const build = async (
    policy: Record<string, Record<string, ComposedPolicy<ScopeCheck>>>,
    opts: Partial<Parameters<typeof createExternalAuth<ScopeCheck, string[]>>[0]> = {}
  ) => {
    const app = Fastify({ logger: false })
    const { applyPolicy } = createExternalAuth<ScopeCheck, string[]>({ prepare: held, evaluate, ...opts })
    await app.register(mercurius, {
      schema: 'type Query { health: Boolean } type Mutation { orAny: Boolean andAll: Boolean }',
      resolvers: { Mutation: { orAny: () => true, andAll: () => true } },
      graphiql: false
    })
    await register(app, { mode: 'external', applyPolicy, policy })
    await app.ready()
    apps.push(app)
    return app
  }

  it('composes AND/OR over host-supplied checks', async () => {
    const app = await build({
      Mutation: {
        orAny: { checks: [{ scope: 'a' }, { scope: 'b' }], relation: 'or' },
        andAll: { checks: [{ scope: 'a' }, { scope: 'b' }], relation: 'and' }
      }
    })
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'b' })).data?.orAny).toBe(true)
    expect((await query(app, 'mutation { andAll }', { 'x-scopes': 'a' })).errors).toBeTruthy()
  })

  it('denies a relation it does not define instead of combining it as anything', async () => {
    const app = await build({
      // A plain-JS host writing the enum spelling bypasses the Relation type.
      Mutation: { andAll: { checks: [{ scope: 'a' }, { scope: 'b' }], relation: 'AND' as never } }
    })
    const res = await query(app, 'mutation { andAll }', { 'x-scopes': 'a,b' })
    expect(res.data?.andAll ?? null).toBeNull()
    expect(res.errors?.[0]?.message).toBe("Invalid auth policy on andAll: relation must be either 'and' or 'or'")
  })

  it('treats relation: null like an absent relation', async () => {
    const app = await build({ Mutation: { andAll: { checks: [{ scope: 'a' }, { scope: 'b' }], relation: null } } })
    expect((await query(app, 'mutation { andAll }', { 'x-scopes': 'b' })).data?.andAll).toBe(true)
  })

  it('denies a checks that is not a list instead of reading it as no checks', async () => {
    const app = await build({ Mutation: { orAny: { checks: { scope: 'a' } as never } } })
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'a' })).errors?.[0]?.message).toBe(
      'Invalid auth policy on orAny: checks must be an array'
    )
  })

  it('a check validate rejects is the field error', async () => {
    const app = await build(
      { Mutation: { orAny: { checks: [{ scope: '' }] } } },
      {
        validate: (check) => {
          if (check.scope === '') throw new Error('scope must not be empty')
        }
      }
    )
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'a' })).errors?.[0]?.message).toBe(
      'scope must not be empty'
    )
  })

  it('denies a field whose policy has no checks', async () => {
    const app = await build({ Mutation: { orAny: { checks: [] } } })
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'a' })).errors).toBeTruthy()
  })
})

describe('createDirectiveAuth: invalid policies', () => {
  const schemaWith = (fields: string) => `
    ${composedDirectiveSdl('auth', 'scope: String!')}
    type Query { health: Boolean }
    type Mutation { ${fields} }
  `

  const build = async (fields: string) => {
    const app = Fastify({ logger: false })
    const composed = createDirectiveAuth<ScopeCheck, string[]>({ parseCheck: parseScope, prepare: held, evaluate })
    await app.register(mercurius, { schema: schemaWith(fields), graphiql: false })
    await register(app, { mode: 'directive', authDirective: composed.directive, applyPolicy: composed.applyPolicy })
    await app.ready()
    apps.push(app)
    return { app, ...composed }
  }

  it('denies a relation it does not define instead of falling back to the default', async () => {
    const { app } = await build('typo: Boolean @auth(checks: [{ scope: "a" }], relation: XOR)')
    expect((await query(app, 'mutation { typo }', { 'x-scopes': 'a' })).errors?.[0]?.message).toBe(
      'Invalid auth policy on typo: relation must be either AND or OR'
    )
  })

  it('checkPolicies passes a schema whose policies all resolve', async () => {
    const { app, checkPolicies } = await build(
      'ok: Boolean @auth(checks: [{ scope: "a" }]) other: Boolean @auth(checks: [{ scope: "b" }], relation: AND)'
    )
    expect(() => checkPolicies(app.graphql.schema)).not.toThrow()
  })

  it('checkPolicies lists every policy that cannot be evaluated, by type, field and position', async () => {
    const { app, checkPolicies } = await build(`
      ok: Boolean @auth(checks: [{ scope: "a" }])
      bad: Boolean @auth(checks: [{ scope: "" }])
      typo: Boolean @auth(checks: [{ scope: "a" }], relation: XOR)
      twice: Boolean @auth(checks: [{ scope: "a" }]) @auth(checks: [{ scope: "" }])
    `)
    let error: unknown
    try {
      checkPolicies(app.graphql.schema)
    } catch (thrown) {
      error = thrown
    }
    expect(error).toMatchObject({ code: INVALID_POLICY_CODE })
    expect((error as Error).message).toBe(
      'Invalid auth policy on the schema: ' +
        'Mutation.bad: each check needs a non-empty `scope` string; ' +
        'Mutation.typo: relation must be either AND or OR; ' +
        'Mutation.twice (@auth #2): each check needs a non-empty `scope` string'
    )
  })

  it('checks its options when it is built', () => {
    const invalid = { code: INVALID_OPTS_CODE }
    expect(() => createDirectiveAuth({ evaluate } as never)).toThrow(expect.objectContaining(invalid))
    expect(() => createDirectiveAuth({ parseCheck: parseScope } as never)).toThrow(
      expect.objectContaining(invalid)
    )
    expect(() => createDirectiveAuth({ parseCheck: parseScope, evaluate, run: 'some' as never })).toThrow(
      "Invalid options: opts.run must be either 'all' or 'first'."
    )
    expect(() =>
      createDirectiveAuth({ parseCheck: parseScope, evaluate, defaultRelation: 'AND' as never })
    ).toThrow(expect.objectContaining(invalid))
    expect(() => createDirectiveAuth({ parseCheck: parseScope, evaluate, directive: 1 as never })).toThrow(
      expect.objectContaining(invalid)
    )
  })
})

describe('createExternalAuth: checkPolicies and options', () => {
  const { checkPolicies } = createExternalAuth<ScopeCheck, string[]>({
    evaluate,
    validate: (check) => {
      if (check.scope === '') throw new Error('scope must not be empty')
    }
  })

  it('passes a policy map whose policies all resolve', () => {
    expect(() =>
      checkPolicies({ Mutation: { a: { checks: [{ scope: 'a' }] }, b: { checks: [], relation: 'and' } } })
    ).not.toThrow()
  })

  it('lists every policy that cannot be evaluated, by type and field', () => {
    expect(() =>
      checkPolicies({
        Mutation: {
          ok: { checks: [{ scope: 'a' }] },
          empty: { checks: [{ scope: '' }] },
          typo: { checks: [], relation: 'OR' as never }
        },
        Secret: { __typePolicy: { checks: 'a' as never } }
      })
    ).toThrow(
      expect.objectContaining({
        code: INVALID_POLICY_CODE,
        message:
          'Invalid auth policy on opts.policy: ' +
          'Mutation.empty: scope must not be empty; ' +
          "Mutation.typo: relation must be either 'and' or 'or'; " +
          'Secret: checks must be an array'
      })
    )
  })

  it('checks its options when it is built', () => {
    expect(() => createExternalAuth({} as never)).toThrow('Invalid options: opts.evaluate must be a function.')
    expect(() => createExternalAuth({ evaluate, validate: 1 as never })).toThrow(
      expect.objectContaining({ code: INVALID_OPTS_CODE })
    )
    expect(() => createExternalAuth({ evaluate, onDeny: 'no' as never })).toThrow(
      expect.objectContaining({ code: INVALID_OPTS_CODE })
    )
  })
})

