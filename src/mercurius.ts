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
import type { DirectiveNode, ValueNode } from 'graphql'
import type { MercuriusContext } from 'mercurius'
import type { ApplyPolicyHandler } from 'mercurius-auth'
import { compose, DEFAULT_RELATION, type Predicate, type Relation } from './compose.js'

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
   * Judge one check against the per-field {@link prepare}d value. Called once per
   * check; the results are combined by the field's relation.
   */
  evaluate: (check: Check, prepared: Prepared) => boolean | Promise<boolean>
  /**
   * Derive a per-field value from the mercurius context once, before any check is
   * evaluated (e.g. extract the caller's identity). If it throws, the thrown Error
   * becomes the field's denial — so a caller can distinguish "not authorized" (see
   * {@link onDeny}) from "authorization unavailable". Omit to pass the raw context
   * to {@link evaluate}.
   */
  prepare?: (context: MercuriusContext) => Prepared | Promise<Prepared>
  /** The Error returned when composition denies (empty checks, or the relation
   * verdict is false). Default {@link defaultDeny} — a coded `Unauthorized`
   * (`extensions.code` + `401`). Pass your own (e.g. a mercurius `ErrorWithProps`)
   * to control the surfaced code/status. */
  onDeny?: () => Error
  /** Relation applied when a field omits its own. Default {@link DEFAULT_RELATION} (`'or'`). */
  defaultRelation?: Relation
  /** Master switch; `false` bypasses enforcement (every field passes). Default `true`. */
  enabled?: boolean
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

/** External-mode per-field policy value: the checks to compose + an optional relation. */
export interface ComposedPolicy<Check> {
  checks: readonly Check[]
  relation?: Relation
}

/** A field's policy resolved once into its evaluation-ready form, or the error a
 * malformed policy produced. Memoised per directive AST node / per policy object. */
type Resolved<Check> = { checks: readonly Check[]; relation: Relation } | { error: Error }

const argValue = (ast: DirectiveNode, name: string): ValueNode | undefined =>
  ast.arguments?.find((arg) => arg.name.value === name)?.value

// GraphQL's SDL rules don't type-check directive-argument enum literals, so map
// the two we define and treat anything else as "unset" (→ defaultRelation).
const parseRelation = (node?: ValueNode): Relation | undefined => {
  if (node?.kind !== 'EnumValue') return undefined
  return node.value === 'OR' ? 'or' : node.value === 'AND' ? 'and' : undefined
}

// The one evaluation path both modes share: empty denies; prepare once (its throw
// is the denial); compose the per-check predicates by relation; a false verdict
// denies via onDeny.
const evaluatePolicy = async <Check, Prepared>(
  resolved: { checks: readonly Check[]; relation: Relation },
  opts: Pick<ComposedAuthOptions<Check, Prepared>, 'evaluate' | 'prepare'> & { onDeny: () => Error },
  context: MercuriusContext
): Promise<boolean | Error> => {
  const { checks, relation } = resolved
  if (checks.length === 0) return opts.onDeny()

  let prepared: Prepared
  try {
    prepared = opts.prepare
      ? await opts.prepare(context)
      : (context as unknown as Prepared)
  } catch (error) {
    return error as Error
  }

  const predicates: Predicate<Prepared>[] = checks.map(
    (check) => (value: Prepared) => opts.evaluate(check, value)
  )
  return (await compose(predicates, relation)(prepared)) || opts.onDeny()
}

/**
 * Build the SDL that defines the composition directive: the `<Name>Relation`
 * enum, the `<Name>Check` input (its body is yours — {@link DEFAULT_CHECK_INPUT}
 * by default), and the `@<name>(checks, relation)` directive. Add it to the
 * schema once (before any field uses the directive).
 */
export const composedDirectiveSdl = (
  directive = 'auth',
  checkInput: string = DEFAULT_CHECK_INPUT
): string => {
  const prefix = directive.charAt(0).toUpperCase() + directive.slice(1)
  return `
  enum ${prefix}Relation { AND OR }

  input ${prefix}Check {
    ${checkInput}
  }

  directive @${directive}(checks: [${prefix}Check!]!, relation: ${prefix}Relation) on FIELD_DEFINITION
`
}

/**
 * Directive mode. Returns the `applyPolicy` (which parses each field's directive
 * AST via your {@link DirectiveComposedAuthOptions.parseCheck}, composes the
 * checks by relation, and returns `true` / an `Error`), the `sdl` to add to the
 * schema, and the `directive` name to pass to mercurius-auth's `authDirective`.
 *
 * @example
 * ```ts
 * import mercuriusAuth from 'mercurius-auth'
 * import { createDirectiveAuth } from 'mercurius-auth-compose'
 *
 * const { applyPolicy, sdl, directive } = createDirectiveAuth({
 *   parseCheck: (node) => myCheckFromAst(node),
 *   evaluate: (check, ctx) => myCheckPasses(check, ctx)
 * })
 * await app.graphql.extendSchema(sdl)
 * app.register(mercuriusAuth, { mode: 'directive', authDirective: directive, applyPolicy })
 * ```
 */
export const createDirectiveAuth = <Check, Prepared = MercuriusContext>(
  options: DirectiveComposedAuthOptions<Check, Prepared>
): { applyPolicy: ApplyPolicy<DirectiveNode>; sdl: string; directive: string } => {
  const {
    evaluate,
    prepare,
    parseCheck,
    onDeny = defaultDeny,
    defaultRelation = DEFAULT_RELATION,
    enabled = true,
    directive = 'auth',
    checkInput = DEFAULT_CHECK_INPUT
  } = options
  const sdl = composedDirectiveSdl(directive, checkInput)
  const resolved = new WeakMap<DirectiveNode, Resolved<Check>>()

  const applyPolicy: ApplyPolicy<DirectiveNode> = async (ast, _parent, _args, context) => {
    if (!enabled) return true
    let entry = resolved.get(ast)
    if (!entry) {
      try {
        const checksNode = argValue(ast, 'checks')
        const checks = checksNode?.kind === 'ListValue' ? checksNode.values.map(parseCheck) : []
        entry = { checks, relation: parseRelation(argValue(ast, 'relation')) ?? defaultRelation }
      } catch (error) {
        entry = { error: error as Error }
      }
      resolved.set(ast, entry)
    }
    return 'error' in entry ? entry.error : evaluatePolicy(entry, { evaluate, prepare, onDeny }, context)
  }

  return { applyPolicy, sdl, directive }
}

/**
 * External mode. Returns the `applyPolicy` reading the {@link ComposedPolicy}
 * values the host maps to fields in mercurius-auth's `policy`. No SDL — the host
 * supplies the checks directly.
 *
 * @example
 * ```ts
 * const { applyPolicy } = createExternalAuth({ evaluate: (check, ctx) => myCheckPasses(check, ctx) })
 * app.register(mercuriusAuth, { mode: 'external', applyPolicy, policy: {
 *   Mutation: { doThing: { checks: [myCheck], relation: 'and' } }
 * } })
 * ```
 */
export const createExternalAuth = <Check, Prepared = MercuriusContext>(
  options: ExternalComposedAuthOptions<Check, Prepared>
): { applyPolicy: ApplyPolicy<ComposedPolicy<Check>> } => {
  const {
    evaluate,
    prepare,
    validate,
    onDeny = defaultDeny,
    defaultRelation = DEFAULT_RELATION,
    enabled = true
  } = options
  const resolved = new WeakMap<object, Resolved<Check>>()

  const applyPolicy: ApplyPolicy<ComposedPolicy<Check>> = async (policy, _parent, _args, context) => {
    if (!enabled) return true
    const memoKey = typeof policy === 'object' && policy !== null ? policy : undefined
    let entry = memoKey ? resolved.get(memoKey) : undefined
    if (!entry) {
      try {
        // A mapped value without a `checks` array (e.g. a __typePolicy) denies
        // (empty) rather than crashing.
        const checks = Array.isArray(policy?.checks) ? policy.checks : []
        if (validate) checks.forEach(validate)
        entry = { checks, relation: policy?.relation ?? defaultRelation }
      } catch (error) {
        entry = { error: error as Error }
      }
      if (memoKey) resolved.set(memoKey, entry)
    }
    return 'error' in entry ? entry.error : evaluatePolicy(entry, { evaluate, prepare, onDeny }, context)
  }

  return { applyPolicy }
}
