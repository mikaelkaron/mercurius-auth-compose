/**
 * The coded errors this package raises. Their codes are those `mercurius-auth`
 * raises for the same mistakes, so an application handles them the same way
 * whichever of the two composes its policies.
 *
 * @packageDocumentation
 */

/** `code` of {@link InvalidOptionsError}. */
export const INVALID_OPTS_CODE = 'MER_AUTH_ERR_INVALID_OPTS'

/** `code` of {@link InvalidPolicyError}. */
export const INVALID_POLICY_CODE = 'MER_AUTH_ERR_INVALID_POLICY'

/**
 * Raised when a composer is built with options it cannot work with: a missing
 * `evaluate`, a `run` that is neither `'all'` nor `'first'`, and the like.
 */
export class InvalidOptionsError extends Error {
  /** {@link INVALID_OPTS_CODE}. */
  readonly code = INVALID_OPTS_CODE
  /** The status mercurius reads off an error it reports. */
  readonly statusCode = 500

  constructor(reason: string) {
    super(`Invalid options: ${reason}`)
    this.name = 'InvalidOptionsError'
  }
}

/**
 * Raised when a policy cannot be evaluated: a relation the mode does not define,
 * an external `checks` that is not a list, a failure signalled with something
 * other than an `Error`, or an `onDeny` that does not return an `Error`. A field
 * whose policy cannot be evaluated is denied with it, and `checkPolicies` throws
 * one listing every such policy.
 */
export class InvalidPolicyError extends Error {
  /** {@link INVALID_POLICY_CODE}. */
  readonly code = INVALID_POLICY_CODE
  /** The status mercurius reads off an error it reports. */
  readonly statusCode = 500

  constructor(on: string, reason: string) {
    super(`Invalid auth policy on ${on}: ${reason}`)
    this.name = 'InvalidPolicyError'
  }
}
