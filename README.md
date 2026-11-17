# mercurius-auth-compose

AND/OR composition of authorization checks for [`mercurius-auth`](https://github.com/mercurius-js/auth) — the composition combinator `mercurius-auth` lacks and [`@fastify/auth`](https://github.com/fastify/fastify-auth) has natively.

It **ships no checks**. You bring the check functions; this composes them with a `relation` (AND / OR) and hands `mercurius-auth` the single `boolean | Error` its `applyPolicy` seam consumes. It is a **companion**, not a fork of `mercurius-auth` and not a wrapper plugin — you register `mercurius-auth` exactly as usual, passing the `applyPolicy` this produces.

## Why

`mercurius-auth` calls `applyPolicy` once per protected field and uses its single result to allow or deny — it has no notion of combining several checks with AND/OR. `@fastify/auth` does (`fastify.auth([a, b], { relation })`). This package fills that gap for the GraphQL/mercurius side, at the only layer that needs it: inside `applyPolicy`.

## Install

```sh
npm install mercurius-auth-compose
```

`mercurius`, `mercurius-auth`, and `graphql` are **optional peers** — needed only for the mercurius layer. The core `compose` combinator has zero dependencies.

## Core combinator

Framework-agnostic. Composes predicates over any context:

```ts
import { compose, DEFAULT_RELATION, type Relation, type Predicate } from 'mercurius-auth-compose'

const guard = compose([checkA, checkB], 'or') // Predicate<C>
await guard(ctx) // true if A or B passes
```

- **OR** grants if any passes; **AND** only if every passes.
- An **empty list denies**.
- **Fail-closed**: any relation that isn't exactly `'or'` combines as AND.
- **Short-circuits** by default, as `@fastify/auth` does: `run: 'first'` runs the checks in order and stops at the first that decides (a pass under OR, a failure under AND). `compose(checks, relation, 'all')` runs every check, concurrently.
- Compositions **nest for free** (no depth limit): `compose([a, b, compose([c, d], 'and')], 'or')`.

## Mercurius directive mode

Provide how one check is parsed from the directive AST and how it's judged; get back the `applyPolicy`, the directive `sdl`, and the `directive` name.

```ts
import Fastify from 'fastify'
import mercurius from 'mercurius'
import mercuriusAuth from 'mercurius-auth'
import { createDirectiveAuth } from 'mercurius-auth-compose'

const { applyPolicy, sdl, directive } = createDirectiveAuth<{ scope: string }, string[]>({
  checkInput: 'scope: String!',
  // parse one `{ scope: "..." }` element of the directive's `checks` list
  parseCheck: (node) => {
    if (node.kind !== 'ObjectValue') throw new Error('each check must be an object')
    const field = node.fields.find((f) => f.name.value === 'scope')
    if (field?.value.kind !== 'StringValue') throw new Error('scope must be a string')
    return { scope: field.value.value }
  },
  // derive the caller's held scopes once per request
  prepare: (ctx) => (ctx.reply.request.headers['x-scopes'] as string ?? '').split(',').filter(Boolean),
  // judge one check
  evaluate: (check, held) => held.includes(check.scope)
})

const app = Fastify()
await app.register(mercurius, { schema })
await app.graphql.extendSchema(sdl) // defines @auth(checks:[AuthCheck!]!, relation: AuthRelation)
app.register(mercuriusAuth, { mode: 'directive', authDirective: directive, applyPolicy })
```

Then tag fields or types: `field: T @auth(checks: [{ scope: "admin" }, { scope: "owner" }], relation: OR)`. A single check needs no list (`checks: { scope: "admin" }`), and the directive is `repeatable`: repeating it ANDs the policies, each enforced on its own.

## Mercurius external mode

No SDL — the host maps `{ checks, relation }` policy values to fields:

```ts
import { createExternalAuth } from 'mercurius-auth-compose'

const { applyPolicy } = createExternalAuth<{ scope: string }, string[]>({
  prepare: (ctx) => held(ctx),
  evaluate: (check, held) => held.includes(check.scope)
})

app.register(mercuriusAuth, {
  mode: 'external',
  applyPolicy,
  policy: { Mutation: { doThing: { checks: [{ scope: 'admin' }], relation: 'and' } } }
})
```

## Policies that cannot be evaluated

A policy that cannot be evaluated denies its field with an error saying why, instead of falling back to something else:

- a check `parseCheck` or `validate` rejects: its error;
- a relation the mode does not define (`relation: XOR`, or `'AND'` in external mode): `relation must be either AND or OR` / `'and' or 'or'`;
- an external `checks` that is there but is not a list: `checks must be an array` (an absent or `null` one is no checks, which denies);
- a `prepare` that throws: its error, for every field of the request that needs it;
- an `onDeny` that returns no `Error`, or a failure signalled with something other than an `Error`: an `InvalidPolicyError`.

A check whose `evaluate` throws did not pass: under OR another check can still grant the field, and its error is the field's error only if the composition denies.

Both modes also return `checkPolicies`, which resolves every policy the way the first request to reach it would, and throws one `InvalidPolicyError` listing each policy that cannot be evaluated — by type and field, and by position when a field carries several. Call it at startup, so a broken policy fails there instead of on every request to its field:

```ts
const { applyPolicy, sdl, directive, checkPolicies } = createDirectiveAuth({ parseCheck, evaluate })
// …register mercurius, extend the schema with `sdl`, register mercurius-auth…
await app.ready()
checkPolicies(app.graphql.schema) // directive mode: the schema

const external = createExternalAuth({ evaluate })
external.checkPolicies(policy) // external mode: the policy map given to mercurius-auth
```

## Errors

| Error                 | `code`                        | Raised when                                                                 |
| --------------------- | ----------------------------- | --------------------------------------------------------------------------- |
| `InvalidOptionsError` | `MER_AUTH_ERR_INVALID_OPTS`   | A composer is built with options it cannot work with (e.g. no `evaluate`).  |
| `InvalidPolicyError`  | `MER_AUTH_ERR_INVALID_POLICY` | A policy cannot be evaluated (see above), and by `checkPolicies`.           |

The codes are those `mercurius-auth` raises for the same mistakes.

## Options

| Option           | Modes             | Description                                                                                             |
| ---------------- | ----------------- | ------------------------------------------------------------------------------------------------------- |
| `evaluate`       | both              | Judge one check against the prepared value → `boolean`. A throw is a check that did not pass.            |
| `prepare`        | both (optional)   | Derive the value the checks are judged against, once per request. A throw becomes the field's error.     |
| `parseCheck`     | directive         | Parse one check from the directive AST; throw to reject a malformed check.                               |
| `validate`       | external (opt.)   | Validate one host-supplied check; throw to reject.                                                       |
| `onDeny`         | both (optional)   | `(context, info) => Error`, may be async: the error on denial. Default: a coded `Unauthorized`.          |
| `defaultRelation`| both (optional)   | Relation when a field omits its own or gives `null`. Default `'or'`.                                     |
| `run`            | both (optional)   | `'first'` stops at the check that decides, `'all'` runs every check concurrently. Default `'first'`.     |
| `directive`      | directive (opt.)  | Directive name (default `auth`); seeds the `<Name>Relation` / `<Name>Check` type names.                  |
| `checkInput`     | directive (opt.)  | SDL body of the `<Name>Check` input. Default `targets: [String!]!`.                                      |

The options are checked when a composer is built: a wrong one throws `InvalidOptionsError`. To turn authorization off, don't register `mercurius-auth`; there is no switch that grants every field.

## License

MIT
