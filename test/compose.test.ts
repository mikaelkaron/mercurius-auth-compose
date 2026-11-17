import { describe, expect, it, vi } from 'vitest'
import { compose, DEFAULT_RELATION, DEFAULT_RUN, type Relation } from '../src/compose.ts'
import { INVALID_OPTS_CODE } from '../src/errors.ts'

const yes = () => true
const no = () => false

describe('compose', () => {
  it("OR grants when any check passes, denies when all fail", async () => {
    expect(await compose([no, yes, no], 'or')(undefined)).toBe(true)
    expect(await compose([no, no], 'or')(undefined)).toBe(false)
  })

  it('AND grants only when every check passes', async () => {
    expect(await compose([yes, yes], 'and')(undefined)).toBe(true)
    expect(await compose([yes, no], 'and')(undefined)).toBe(false)
  })

  it('an empty list denies under either relation', async () => {
    expect(await compose([], 'or')(undefined)).toBe(false)
    expect(await compose([], 'and')(undefined)).toBe(false)
  })

  it("defaults to OR (matching @fastify/auth)", async () => {
    expect(DEFAULT_RELATION).toBe('or')
    expect(await compose([no, yes])(undefined)).toBe(true)
    expect(await compose([no, no])(undefined)).toBe(false)
  })

  it('is fail-closed: any relation that is not "or" combines as AND', async () => {
    const bogus = 'AND' as unknown as Relation // wrong case, e.g. from a plain-JS host
    expect(await compose([yes, no], bogus)(undefined)).toBe(false)
    expect(await compose([yes, yes], bogus)(undefined)).toBe(true)
  })

  it('awaits async predicates', async () => {
    const asyncYes = async () => true
    const asyncNo = async () => false
    expect(await compose([asyncNo, asyncYes], 'or')(undefined)).toBe(true)
    expect(await compose([asyncYes, asyncNo], 'and')(undefined)).toBe(false)
  })

  it('passes the shared context to every predicate', async () => {
    const seen: number[] = []
    const record = (ctx: number) => {
      seen.push(ctx)
      return true
    }
    await compose([record, record], 'and')(42)
    expect(seen).toEqual([42, 42])
  })

  it('nests without a depth limit: a OR b OR (c AND d)', async () => {
    const inner = compose([yes, no], 'and') // c AND d → false
    expect(await compose([no, no, inner], 'or')(undefined)).toBe(false)
    const inner2 = compose([yes, yes], 'and') // → true
    expect(await compose([no, no, inner2], 'or')(undefined)).toBe(true)
  })

  it("defaults run to 'first' (matching @fastify/auth)", () => {
    expect(DEFAULT_RUN).toBe('first')
  })

  it("run 'first' stops at the first check that decides: a pass under OR", async () => {
    const a = vi.fn(() => true)
    const b = vi.fn(() => true)
    expect(await compose([a, b], 'or')(undefined)).toBe(true)
    expect(a).toHaveBeenCalledOnce()
    expect(b).not.toHaveBeenCalled()
  })

  it("run 'first' stops at the first check that decides: a failure under AND", async () => {
    const a = vi.fn(() => false)
    const b = vi.fn(() => true)
    expect(await compose([a, b], 'and')(undefined)).toBe(false)
    expect(b).not.toHaveBeenCalled()
  })

  it("run 'first' runs the checks in order, one at a time", async () => {
    const order: string[] = []
    const slow = async () => {
      await new Promise((resolve) => setTimeout(resolve, 10))
      order.push('slow')
      return false
    }
    const fast = () => {
      order.push('fast')
      return false
    }
    expect(await compose([slow, fast], 'or')(undefined)).toBe(false)
    expect(order).toEqual(['slow', 'fast'])
  })

  it("run 'all' evaluates every check, so side effects always run", async () => {
    const a = vi.fn(() => true)
    const b = vi.fn(() => true)
    await compose([a, b], 'or', 'all')(undefined)
    expect(a).toHaveBeenCalledOnce()
    expect(b).toHaveBeenCalledOnce()
  })

  it('rejects checks that are not a list', () => {
    expect(() => compose(yes as never)).toThrow(expect.objectContaining({ code: INVALID_OPTS_CODE }))
  })
})
