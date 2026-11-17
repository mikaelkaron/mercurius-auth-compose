/**
 * The mercurius layer: turn a caller-supplied check into a mercurius-auth
 * `applyPolicy` that composes multiple checks with an AND/OR `relation` — the
 * capability `mercurius-auth` lacks and `@fastify/auth` has. This is a
 * *companion*, not a fork or a wrapper plugin: it produces an `applyPolicy` you
 * pass to `mercurius-auth` normally (its one decision seam), because AND/OR over
 * N checks collapses to the single `boolean | Error` that seam consumes.
 *
 * The `checks` + `relation` directive convention is defined here (mercurius-auth
 * parses no directive arguments itself); the *shape* of a check and how it is
 * judged are yours, injected via {@link ComposedAuthOptions}.
 *
 * @packageDocumentation
 */
import type { DirectiveNode, GraphQLResolveInfo, GraphQLSchema, ValueNode } from 'graphql'
import type { MercuriusContext } from 'mercurius'
import type { ApplyPolicyHandler } from 'mercurius-auth'
import { compose, DEFAULT_RELATION, DEFAULT_RUN, type Predicate, type Relation, type Run } from './compose.js'
import { InvalidOptionsError, InvalidPolicyError } from './errors.js'

/** A mercurius-auth `applyPolicy` handler over a per-field policy of shape `P`. */
export type ApplyPolicy<P> = ApplyPolicyHandler<unknown, unknown, MercuriusContext, P>

/** The default check-input SDL body (`targets: [String!]!`) — the common
 * "held-strings overlap" model. Override via {@link DirectiveComposedAuthOptions.checkInput}. */
export const DEFAULT_CHECK_INPUT = 'targets: [String!]!'

/** `extensions.code` of the fallback denial. */
export const UNAUTHORIZED_CODE = 'UNAUTHORIZED'

/**
 * The fallback denial used when a consumer provides no
 * {@link ComposedAuthOptions.onDeny}. It is shaped like a mercurius
 * `ErrorWithProps` — an `extensions.code` plus a `statusCode`, which is exactly
 * what mercurius reads (duck-typed) to build the GraphQL field error — but is not
 * imported from mercurius, so this combinator stays framework-agnostic (mercurius
 * is an optional peer). Consumers typically pass their own `onDeny` returning a
 * real `ErrorWithProps`.
 */
export const defaultDeny = (): Error =>
  Object.assign(new Error('Unauthorized'), {
    extensions: { code: UNAUTHORIZED_CODE },
    statusCode: 401
  })

/** Seams shared by both modes — the check-specific behaviour the caller injects. */
export interface ComposedAuthOptions<Check, Prepared = MercuriusContext> {
  /**
   * Judge one check against the {@link prepare}d value. Called once per check of
   * the field's policy; the results are combined by the field's relation. A check
   * that throws is a check that did not pass: its error becomes the field's error
   * only if the composition ends up denying, so under OR another check can still
   * grant.
   */
  evaluate: (check: Check, prepared: Prepared) => boolean | Promise<boolean>
  /**
   * Derive the value the checks are judged against from the mercurius context. It
   * runs once per request: the first protected field to need it calls it, and
   * every other protected field of the same request reuses the result. If it
   * throws, the thrown Error becomes the error of every field that needs it — so a
   * caller can distinguish "not authorized" (see {@link onDeny}) from
   * "authorization unavailable". Omit to pass the raw context to {@link evaluate}.
   */
  prepare?: (context: MercuriusContext) => Prepared | Promise<Prepared>
  /**
   * The Error returned when composition denies (empty checks, or the relation
   * verdict is false); it may be async. Default {@link defaultDeny} — a coded
   * `Unauthorized` (`extensions.code` + `401`). Pass your own (e.g. a mercurius
   * `ErrorWithProps`) to control the surfaced code/status. It must return (or
   * resolve to) an `Error`: anything else denies the field with an
   * {@link InvalidPolicyError}, since mercurius-auth reads a truthy non-`Error` as
   * a grant.
   */
  onDeny?: (context: MercuriusContext, info: GraphQLResolveInfo) => Error | Promise<Error>
  /** Relation applied when a field omits its own, or gives `null`. Default
   * {@link DEFAULT_RELATION} (`'or'`). */
  defaultRelation?: Relation
  /** How many checks of a field's policy run. Default {@link DEFAULT_RUN}
   * (`'first'`): in order, stopping at the first check that decides the outcome;
   * `'all'` runs every check, concurrently. */
  run?: Run
}

/** Directive-mode options: {@link ComposedAuthOptions} plus how to parse one check
 * from the directive AST and how to name/shape the directive. */
export interface DirectiveComposedAuthOptions<Check, Prepared = MercuriusContext>
  extends ComposedAuthOptions<Check, Prepared> {
  /** Parse one element of the directive's `checks` list (a GraphQL value node) into
   * a `Check`. Throw to reject a malformed check — the throw becomes a per-field
   * policy error. */
  parseCheck: (node: ValueNode) => Check
  /** The directive name (default `auth`); the shared type names are derived from it
   * (PascalCased), so several directives can coexist in one schema. */
  directive?: string
  /** SDL body of the `<Name>Check` input type. Default {@link DEFAULT_CHECK_INPUT}. */
  checkInput?: string
}

/** External-mode options: {@link ComposedAuthOptions} plus optional per-check
 * validation of the host-supplied policy values. */
export interface ExternalComposedAuthOptions<Check, Prepared = MercuriusContext>
  extends ComposedAuthOptions<Check, Prepared> {
  /** Validate one host-supplied check; throw to reject it (becomes a per-field
   * policy error). Omit to accept any shape (evaluated as-is). */
  validate?: (check: Check) => void
}

/** External-mode per-field policy value: the checks to compose + an optional
 * relation (`null` is the same as none). */
export interface ComposedPolicy<Check> {
  checks: readonly Check[]
  relation?: Relation | null
}

/** The external-mode policy map mercurius-auth takes as `policy`: type name →
 * field name (or `__typePolicy`) → policy value. */
export type ComposedPolicyMap<Check> = Record<string, Record<string, ComposedPolicy<Check>>>

/** A field's policy resolved once into its evaluation-ready form, or the reason it
 * cannot be evaluated. Memoised per directive AST node / per policy object. */
type Resolved<Check> = { checks: readonly Check[]; relation: Relation } | { invalid: unknown }

/** What the shared evaluation path needs of the options, defaults applied. */
interface EvaluateOptions<Check, Prepared> {
  evaluate: (check: Check, prepared: Prepared) => boolean | Promise<boolean>
  prepare: ((context: MercuriusContext) => Promise<Prepared>) | undefined
  onDeny: (context: MercuriusContext, info: GraphQLResolveInfo) => Error | Promise<Error>
  run: Run
}

// A policy that spells its relation in a way this package does not define is an
// authoring mistake, reported as such instead of silently falling back — the way
// `@fastify/auth` rejects a relation that is neither 'or' nor 'and'.
const INVALID_DIRECTIVE_RELATION = 'relation must be either AND or OR'
const INVALID_EXTERNAL_RELATION = "relation must be either 'and' or 'or'"
const INVALID_EXTERNAL_CHECKS = 'checks must be an array'

const isFunction = (value: unknown): boolean => typeof value === 'function'

// The options are checked when the composer is built, so a plain-JS host's typo
// fails at startup instead of on every request.
const validateOptions = (opts: unknown, mode: 'directive' | 'external'): void => {
  if (typeof opts !== 'object' || opts === null) throw new InvalidOptionsError('opts must be an object.')
  const o = opts as Record<string, unknown>
  if (!isFunction(o.evaluate)) throw new InvalidOptionsError('opts.evaluate must be a function.')
  if (o.prepare !== undefined && !isFunction(o.prepare)) {
    throw new InvalidOptionsError('opts.prepare must be a function.')
  }
  if (o.onDeny !== undefined && !isFunction(o.onDeny)) {
    throw new InvalidOptionsError('opts.onDeny must be a function.')
  }
  if (o.defaultRelation !== undefined && o.defaultRelation !== 'and' && o.defaultRelation !== 'or') {
    throw new InvalidOptionsError("opts.defaultRelation must be either 'and' or 'or'.")
  }
  if (o.run !== undefined && o.run !== 'all' && o.run !== 'first') {
    throw new InvalidOptionsError("opts.run must be either 'all' or 'first'.")
  }
  if (mode === 'external') {
    if (o.validate !== undefined && !isFunction(o.validate)) {
      throw new InvalidOptionsError('opts.validate must be a function.')
    }
    return
  }
  if (!isFunction(o.parseCheck)) throw new InvalidOptionsError('opts.parseCheck must be a function.')
  if (o.directive !== undefined && typeof o.directive !== 'string') {
    throw new InvalidOptionsError('opts.directive must be a string.')
  }
  if (o.checkInput !== undefined && typeof o.checkInput !== 'string') {
    throw new InvalidOptionsError('opts.checkInput must be a string.')
  }
}

const argValue = (ast: DirectiveNode, name: string): ValueNode | undefined =>
  ast.arguments?.find((arg) => arg.name.value === name)?.value

// The value nodes of the `checks` argument. GraphQL coerces a single value where a
// list is expected, so `checks: { ... }` is a list of one check and is read as such.
// An argument that is absent or null is no checks at all, which denies.
const checkNodes = (node: ValueNode | undefined): readonly ValueNode[] => {
  if (node === undefined || node.kind === 'NullValue') return []
  return node.kind === 'ListValue' ? node.values : [node]
}

// GraphQL's SDL rules don't type-check directive-argument enum literals, so map
// the two we define and report anything else.
const directiveRelation = (node: ValueNode): Relation | undefined => {
  if (node.kind !== 'EnumValue') return undefined
  return node.value === 'OR' ? 'or' : node.value === 'AND' ? 'and' : undefined
}

const externalRelation = (relation: unknown): Relation | undefined =>
  relation === 'and' || relation === 'or' ? relation : undefined

// A reason that is not an `Error` must never reach mercurius-auth as-is, where a
// truthy non-Error reads as "granted", so it is coerced into a coded error naming
// the field.
const asPolicyError = (reason: unknown, fieldName: string): Error =>
  reason instanceof Error ? reason : new InvalidPolicyError(fieldName, String(reason))

// What `onDeny` returns is application code and is checked: a denial must never
// become a grant by way of the hook meant to shape it.
const deny = async <Check, Prepared>(
  opts: EvaluateOptions<Check, Prepared>,
  context: MercuriusContext,
  info: GraphQLResolveInfo
): Promise<Error> => {
  const error: unknown = await opts.onDeny(context, info)
  return error instanceof Error ? error : new InvalidPolicyError(info.fieldName, 'onDeny must return an Error')
}

// `prepare` derives its value from the context alone, so it runs once per request
// context rather than once per protected field: a list of 100 rows with 3 protected
// fields each would otherwise call it 300 times. The promise is cached, so fields
// resolved concurrently share the one call, and a failure is every field's error.
// The cache belongs to one composer and holds the context weakly, so an entry goes
// away with its request.
const prepareOnce = <Prepared>(
  prepare: (context: MercuriusContext) => Prepared | Promise<Prepared>
): ((context: MercuriusContext) => Promise<Prepared>) => {
  const prepared = new WeakMap<object, Promise<Prepared>>()
  return (context) => {
    let value = prepared.get(context)
    if (value === undefined) {
      value = (async () => prepare(context))()
      prepared.set(context, value)
    }
    return value
  }
}

// The evaluation path both modes share: a policy that cannot be evaluated denies
// with the reason it was rejected for, an empty check list denies, `prepare` runs
// once per request, and the per-check verdicts are combined by the field's relation.
const evaluatePolicy = async <Check, Prepared>(
  resolved: Resolved<Check>,
  opts: EvaluateOptions<Check, Prepared>,
  context: MercuriusContext,
  info: GraphQLResolveInfo
): Promise<boolean | Error> => {
  if ('invalid' in resolved) return asPolicyError(resolved.invalid, info.fieldName)

  const { checks, relation } = resolved
  if (checks.length === 0) return deny(opts, context, info)

  let prepared: Prepared
  try {
    prepared = opts.prepare ? await opts.prepare(context) : (context as unknown as Prepared)
  } catch (error) {
    return asPolicyError(error, info.fieldName)
  }

  // A check that throws is a check that did not pass, the way a `@fastify/auth`
  // verifier that calls `done(err)` is: its error is reported only if the
  // composition ends up denying, so one failing check cannot deny a field that
  // another check grants under OR.
  let checkError: { error: unknown } | undefined
  const predicates: Predicate<Prepared>[] = checks.map((check) => async (value: Prepared) => {
    try {
      return await opts.evaluate(check, value)
    } catch (error) {
      checkError ??= { error }
      return false
    }
  })

  if (await compose(predicates, relation, opts.run)(prepared)) return true
  return checkError ? asPolicyError(checkError.error, info.fieldName) : deny(opts, context, info)
}

// The message a policy that cannot be evaluated is reported with by `checkPolicies`.
const invalidReason = <Check>(resolved: Resolved<Check>): string | undefined => {
  if (!('invalid' in resolved)) return undefined
  return resolved.invalid instanceof Error ? resolved.invalid.message : String(resolved.invalid)
}

// Resolve every policy value of a type → field → value(s) map and throw one
// InvalidPolicyError listing each that cannot be evaluated, by type and field, and
// by position when a field or type carries several.
const checkPolicyMap = (
  entries: Iterable<[typeName: string, fieldName: string, values: readonly unknown[]]>,
  reasonOf: (value: unknown) => string | undefined,
  on: string,
  label: string
): void => {
  const failures: string[] = []
  for (const [typeName, fieldName, values] of entries) {
    values.forEach((value, index) => {
      const reason = reasonOf(value)
      if (reason === undefined) return
      let coordinate = fieldName === '__typePolicy' ? typeName : `${typeName}.${fieldName}`
      if (values.length > 1) coordinate += ` (${label} #${index + 1})`
      failures.push(`${coordinate}: ${reason}`)
    })
  }
  if (failures.length > 0) throw new InvalidPolicyError(on, failures.join('; '))
}

/**
 * Build the SDL that defines the composition directive: the `<Name>Relation`
 * enum, the `<Name>Check` input (its body is yours — {@link DEFAULT_CHECK_INPUT}
 * by default), and the `@<name>(checks, relation)` directive. Add it to the
 * schema once (before any field uses the directive).
 *
 * The directive is `repeatable`, so repeating it on a field or type ANDs the
 * composed policies — mercurius-auth enforces each occurrence on its own.
 */
export const composedDirectiveSdl = (
  directive = 'auth',
  checkInput: string = DEFAULT_CHECK_INPUT
): string => {
  const prefix = directive.charAt(0).toUpperCase() + directive.slice(1)
  return `
  enum ${prefix}Relation {
    AND
    OR
  }

  input ${prefix}Check {
    ${checkInput}
  }

  directive @${directive}(
    checks: [${prefix}Check!]!
    relation: ${prefix}Relation
  ) repeatable on OBJECT | FIELD_DEFINITION
`
}

/**
 * Directive mode. Returns the `applyPolicy` (which parses each field's directive
 * AST via your {@link DirectiveComposedAuthOptions.parseCheck}, composes the
 * checks by relation, and returns `true` / an `Error`), the `sdl` to add to the
 * schema, the `directive` name to pass to mercurius-auth's `authDirective`, and
 * `checkPolicies`, which resolves every policy of a schema the way the first
 * request to reach it would and throws one {@link InvalidPolicyError} listing
 * each policy that cannot be evaluated — call it at startup, once the schema is
 * final, to fail there instead of on every request to a broken field.
 *
 * @example
 * ```ts
 * import mercuriusAuth from 'mercurius-auth'
 * import { createDirectiveAuth } from 'mercurius-auth-compose'
 *
 * const { applyPolicy, sdl, directive, checkPolicies } = createDirectiveAuth({
 *   parseCheck: (node) => myCheckFromAst(node),
 *   evaluate: (check, ctx) => myCheckPasses(check, ctx)
 * })
 * await app.graphql.extendSchema(sdl)
 * app.register(mercuriusAuth, { mode: 'directive', authDirective: directive, applyPolicy })
 * await app.ready()
 * checkPolicies(app.graphql.schema)
 * ```
 */
export const createDirectiveAuth = <Check, Prepared = MercuriusContext>(
  options: DirectiveComposedAuthOptions<Check, Prepared>
): {
  applyPolicy: ApplyPolicy<DirectiveNode>
  sdl: string
  directive: string
  checkPolicies: (schema: GraphQLSchema) => void
} => {
  validateOptions(options, 'directive')
  const {
    evaluate,
    prepare,
    parseCheck,
    onDeny = defaultDeny,
    defaultRelation = DEFAULT_RELATION,
    run = DEFAULT_RUN,
    directive = 'auth',
    checkInput = DEFAULT_CHECK_INPUT
  } = options
  const opts: EvaluateOptions<Check, Prepared> = {
    evaluate,
    prepare: prepare ? prepareOnce(prepare) : undefined,
    onDeny,
    run
  }

  // The AST of a directive is stable for the lifetime of the schema, so each
  // field's checks are parsed once rather than on every request.
  const resolved = new WeakMap<DirectiveNode, Resolved<Check>>()
  const resolve = (ast: DirectiveNode): Resolved<Check> => {
    let entry = resolved.get(ast)
    if (entry === undefined) {
      try {
        const relationNode = argValue(ast, 'relation')
        const relation =
          relationNode === undefined || relationNode.kind === 'NullValue'
            ? defaultRelation
            : directiveRelation(relationNode)
        entry =
          relation === undefined
            ? { invalid: INVALID_DIRECTIVE_RELATION }
            : { checks: checkNodes(argValue(ast, 'checks')).map((node) => parseCheck(node)), relation }
      } catch (error) {
        entry = { invalid: error }
      }
      resolved.set(ast, entry)
    }
    return entry
  }

  const applyPolicy: ApplyPolicy<DirectiveNode> = (ast, _parent, _args, context, info) =>
    evaluatePolicy(resolve(ast), opts, context, info)

  // The directives mercurius-auth protects: those on a type's or a field's own
  // definition, as it reads them.
  const directivesOf = (node: { directives?: readonly DirectiveNode[] } | null | undefined) =>
    node?.directives?.filter((d) => d.name.value === directive) ?? []

  function* schemaPolicies(schema: GraphQLSchema): Generator<[string, string, readonly DirectiveNode[]]> {
    for (const type of Object.values(schema.getTypeMap())) {
      const typeDirectives = directivesOf(type.astNode)
      if (typeDirectives.length > 0) yield [type.name, '__typePolicy', typeDirectives]
      if (!('getFields' in type)) continue
      for (const field of Object.values(type.getFields())) {
        const fieldDirectives = directivesOf(field.astNode)
        if (fieldDirectives.length > 0) yield [type.name, field.name, fieldDirectives]
      }
    }
  }

  const checkPolicies = (schema: GraphQLSchema): void =>
    checkPolicyMap(
      schemaPolicies(schema),
      (ast) => invalidReason(resolve(ast as DirectiveNode)),
      'the schema',
      `@${directive}`
    )

  return { applyPolicy, sdl: composedDirectiveSdl(directive, checkInput), directive, checkPolicies }
}

/**
 * External mode. Returns the `applyPolicy` reading the {@link ComposedPolicy}
 * values the host maps to fields in mercurius-auth's `policy`, and
 * `checkPolicies`, which resolves every value of that map the way the first
 * request to reach it would and throws one {@link InvalidPolicyError} listing
 * each policy that cannot be evaluated. No SDL — the host supplies the checks
 * directly.
 *
 * @example
 * ```ts
 * const { applyPolicy, checkPolicies } = createExternalAuth({
 *   evaluate: (check, ctx) => myCheckPasses(check, ctx)
 * })
 * const policy = { Mutation: { doThing: { checks: [myCheck], relation: 'and' } } }
 * checkPolicies(policy)
 * app.register(mercuriusAuth, { mode: 'external', applyPolicy, policy })
 * ```
 */
export const createExternalAuth = <Check, Prepared = MercuriusContext>(
  options: ExternalComposedAuthOptions<Check, Prepared>
): {
  applyPolicy: ApplyPolicy<ComposedPolicy<Check>>
  checkPolicies: (policy: ComposedPolicyMap<Check>) => void
} => {
  validateOptions(options, 'external')
  const {
    evaluate,
    prepare,
    validate,
    onDeny = defaultDeny,
    defaultRelation = DEFAULT_RELATION,
    run = DEFAULT_RUN
  } = options
  const opts: EvaluateOptions<Check, Prepared> = {
    evaluate,
    prepare: prepare ? prepareOnce(prepare) : undefined,
    onDeny,
    run
  }

  const resolved = new WeakMap<object, Resolved<Check>>()
  const resolve = (policy: ComposedPolicy<Check> | null | undefined): Resolved<Check> => {
    const memoKey = typeof policy === 'object' && policy !== null ? policy : undefined
    let entry = memoKey ? resolved.get(memoKey) : undefined
    if (entry === undefined) {
      try {
        // A mapped value without `checks` — a `__typePolicy` of another shape, for
        // instance — denies as an empty policy. A `checks` that is there but is not
        // a list is an authoring mistake, reported as such rather than read as no
        // checks.
        const checks: unknown = policy?.checks ?? []
        const relation = policy?.relation == null ? defaultRelation : externalRelation(policy.relation)
        if (!Array.isArray(checks)) {
          entry = { invalid: INVALID_EXTERNAL_CHECKS }
        } else if (relation === undefined) {
          entry = { invalid: INVALID_EXTERNAL_RELATION }
        } else {
          if (validate) checks.forEach((check: Check) => validate(check))
          entry = { checks: checks as readonly Check[], relation }
        }
      } catch (error) {
        entry = { invalid: error }
      }
      if (memoKey) resolved.set(memoKey, entry)
    }
    return entry
  }

  const applyPolicy: ApplyPolicy<ComposedPolicy<Check>> = (policy, _parent, _args, context, info) =>
    evaluatePolicy(resolve(policy), opts, context, info)

  function* mapPolicies(policy: ComposedPolicyMap<Check>): Generator<[string, string, readonly unknown[]]> {
    for (const [typeName, typePolicy] of Object.entries(policy)) {
      for (const [fieldName, value] of Object.entries(typePolicy)) {
        yield [typeName, fieldName, Array.isArray(value) ? value : [value]]
      }
    }
  }

  const checkPolicies = (policy: ComposedPolicyMap<Check>): void =>
    checkPolicyMap(
      mapPolicies(policy),
      (value) => invalidReason(resolve(value as ComposedPolicy<Check>)),
      'opts.policy',
      'policy'
    )

  return { applyPolicy, checkPolicies }
}
