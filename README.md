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
  // derive the caller's held scopes once per field
  prepare: (ctx) => (ctx.reply.request.headers['x-scopes'] as string ?? '').split(',').filter(Boolean),
  // judge one check
  evaluate: (check, held) => held.includes(check.scope)
})

const app = Fastify()
await app.register(mercurius, { schema })
await app.graphql.extendSchema(sdl) // defines @auth(checks:[AuthCheck!]!, relation: AuthRelation)
app.register(mercuriusAuth, { mode: 'directive', authDirective: directive, applyPolicy })
```

Then tag fields: `field: T @auth(checks: [{ scope: "admin" }, { scope: "owner" }], relation: OR)`.

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

## Options

| Option           | Modes             | Description                                                                                             |
| ---------------- | ----------------- | ------------------------------------------------------------------------------------------------------- |
| `evaluate`       | both              | Judge one check against the prepared value → `boolean`.                                                  |
| `prepare`        | both (optional)   | Derive a per-field value from the context once. A throw becomes the field's denial (distinct from deny). |
| `parseCheck`     | directive         | Parse one check from the directive AST; throw to reject a malformed check.                               |
| `validate`       | external (opt.)   | Validate one host-supplied check; throw to reject.                                                       |
| `onDeny`         | both (optional)   | The `Error` returned on denial. Default: generic `Unauthorized`.                                         |
| `defaultRelation`| both (optional)   | Relation when a field omits its own. Default `'or'`.                                                     |
| `enabled`        | both (optional)   | `false` bypasses enforcement. Default `true`.                                                            |
| `directive`      | directive (opt.)  | Directive name (default `auth`); seeds the `<Name>Relation` / `<Name>Check` type names.                  |
| `checkInput`     | directive (opt.)  | SDL body of the `<Name>Check` input. Default `targets: [String!]!`.                                      |

## License

MIT
