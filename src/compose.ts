/**
 * The framework-agnostic core: compose auth *check functions* with an AND/OR
 * relation. This layer knows nothing about mercurius, graphql, or what a check
 * inspects — it only reduces a set of predicates over a shared context. It is the
 * mercurius-world analog of what `@fastify/auth` does for fastify verifiers.
 *
 * @packageDocumentation
 */
import { InvalidOptionsError } from './errors.js'

/** How a list of checks combines. */
export type Relation = 'and' | 'or'

/**
 * How many checks run: `'first'` stops at the first check that decides the
 * outcome, `'all'` evaluates every check, concurrently.
 */
export type Run = 'all' | 'first'

/**
 * Default composition when a policy omits the relation. Matches `@fastify/auth`'s
 * own default so REST and GraphQL surfaces agree.
 */
export const DEFAULT_RELATION: Relation = 'or'

/**
 * Default number of checks that run. Matches `@fastify/auth`'s own default, so an
 * expensive check does not run once a cheaper one has already decided.
 */
export const DEFAULT_RUN: Run = 'first'

/**
 * A single check: a predicate over an arbitrary context `C`, returning whether
 * the caller is granted. Sync or async. The package ships *no* predicates — the
 * caller brings them (that is the whole point, like `@fastify/auth`).
 */
export type Predicate<C> = (ctx: C) => boolean | Promise<boolean>

/**
 * Compose predicates into one predicate combined by `relation`.
 *
 * - **OR** grants if any check passes; **AND** grants only if every check passes.
 * - An **empty list denies** (`false`) — a guard with no checks must never pass.
 * - **Fail-closed**: any relation that isn't exactly `'or'` combines as AND, so an
 *   unvalidated value from a plain-JS host (e.g. `'AND'` in the wrong case) can
 *   never fail open.
 *
 * With `run: 'first'` (the default) the checks run in order and evaluation stops
 * at the first check that decides the outcome: one that passes under OR, or one
 * that fails under AND. With `run: 'all'` every check runs, concurrently, so a
 * check's side effects, if any, always run.
 *
 * The returned value is itself a {@link Predicate}, so compositions nest for free:
 * `compose([a, b, compose([c, d], 'and')], 'or')` = `a OR b OR (c AND d)` — with
 * no depth limit (unlike `@fastify/auth`'s single level of sub-arrays).
 */
export const compose = <C>(
  checks: readonly Predicate<C>[],
  relation: Relation = DEFAULT_RELATION,
  run: Run = DEFAULT_RUN
): Predicate<C> => {
  if (!Array.isArray(checks)) throw new InvalidOptionsError('checks must be an array.')

  // Under OR the first check that passes decides the outcome, under AND the first
  // check that fails does.
  const decisive = relation === 'or'

  return async (ctx: C): Promise<boolean> => {
    if (checks.length === 0) return false

    if (run === 'first') {
      for (const check of checks) {
        if (Boolean(await check(ctx)) === decisive) return decisive
      }
      return !decisive
    }

    const results = await Promise.all(checks.map((check) => check(ctx)))
    return decisive ? results.some(Boolean) : results.every(Boolean)
  }
}
