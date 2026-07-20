import Fastify, { type FastifyInstance, type FastifyPluginAsync } from 'fastify'
import type { ValueNode } from 'graphql'
import mercurius, { type MercuriusContext } from 'mercurius'
import mercuriusAuth, { type MercuriusAuthOptions } from 'mercurius-auth'
import { afterEach, describe, expect, it } from 'vitest'
import {
  composedDirectiveSdl,
  createDirectiveAuth,
  createExternalAuth,
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
    .then((res) => res.json() as { data?: Record<string, unknown>; errors?: { message: string }[] })

afterEach(async () => {
  await Promise.all(apps.splice(0).map((a) => a.close()))
})

describe('composedDirectiveSdl', () => {
  it('names the shared types after the directive so several can coexist', () => {
    const auth = composedDirectiveSdl('auth')
    expect(auth).toContain('enum AuthRelation { AND OR }')
    expect(auth).toContain('input AuthCheck {')
    expect(auth).toContain('directive @auth(checks: [AuthCheck!]!, relation: AuthRelation) on FIELD_DEFINITION')

    const guard = composedDirectiveSdl('guard')
    expect(guard).toContain('enum GuardRelation { AND OR }')
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
        }
      `,
      resolvers: {
        Mutation: { orAny: () => true, andAll: () => true, defaulted: () => true, none: () => true, bad: () => true }
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

  it('enabled:false bypasses enforcement', async () => {
    const app = await build({ enabled: false })
    expect((await query(app, 'mutation { andAll }')).data?.andAll).toBe(true)
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

  it('is fail-closed: an unrecognized relation value combines as AND, never fails open', async () => {
    const app = await build({
      // A plain-JS host writing the enum spelling bypasses the Relation type.
      Mutation: { andAll: { checks: [{ scope: 'a' }, { scope: 'b' }], relation: 'AND' as never } }
    })
    expect((await query(app, 'mutation { andAll }', { 'x-scopes': 'a' })).errors).toBeTruthy()
    expect((await query(app, 'mutation { andAll }', { 'x-scopes': 'a,b' })).data?.andAll).toBe(true)
  })

  it('denies a field whose policy has no checks', async () => {
    const app = await build({ Mutation: { orAny: { checks: [] } } })
    expect((await query(app, 'mutation { orAny }', { 'x-scopes': 'a' })).errors).toBeTruthy()
  })
})
