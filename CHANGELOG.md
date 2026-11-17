# [2.0.0](https://github.com/mikaelkaron/mercurius-auth-compose/compare/v1.0.0...v2.0.0) (2026-11-17)


### Features

* compose policies as mercurius-auth's composed policies do ([b62d43e](https://github.com/mikaelkaron/mercurius-auth-compose/commit/b62d43e342e3758efddf7d1e5c63dcc8c8a08dad)), closes [mercurius-js/auth#137](https://github.com/mercurius-js/auth/issues/137) [#153](https://github.com/mikaelkaron/mercurius-auth-compose/issues/153)


### BREAKING CHANGES

* `enabled` is removed, checks short-circuit by default
(`run: 'first'`), an undefined relation or a non-list external `checks` now
denies with an error, and the directive SDL is repeatable on OBJECT too.

# 1.0.0 (2026-07-20)


### Features

* add test:coverage; make the fallback denial a coded error ([b91b2cc](https://github.com/mikaelkaron/mercurius-auth-compose/commit/b91b2cc94d7b55115ad088e1543c28d8f54176a9))
* mercurius-auth-compose — AND/OR check composition for mercurius-auth ([77d8514](https://github.com/mikaelkaron/mercurius-auth-compose/commit/77d8514a0c0acda00e0bf293493fdd55257727ab))
