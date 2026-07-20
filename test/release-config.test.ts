import { afterEach, describe, expect, it } from 'vitest'
import config, { allPlugins, buildSkipFilter, stepId } from '../release.config.mjs'

const NPM = '@semantic-release/npm'

afterEach(() => {
  delete process.env.SEMREL_SKIP_STEPS
})

describe('allPlugins', () => {
  it('is an array', () => {
    expect(Array.isArray(allPlugins)).toBe(true)
  })

  it('contains exactly one @semantic-release/npm entry', () => {
    const npm = allPlugins.filter((e) => Array.isArray(e) && e[0] === NPM)
    expect(npm).toHaveLength(1)
  })

  it('includes commit-analyzer and release-notes-generator (unskippable string entries)', () => {
    expect(allPlugins).toContain('@semantic-release/commit-analyzer')
    expect(allPlugins).toContain('@semantic-release/release-notes-generator')
  })
})

describe('stepId', () => {
  it('returns the name when no suffix', () => {
    expect(stepId(NPM)).toBe(NPM)
  })

  it('returns name:suffix when a suffix is provided', () => {
    expect(stepId('@semantic-release/exec', 'build')).toBe('@semantic-release/exec:build')
  })
})

describe('buildSkipFilter', () => {
  it('keeps every entry when SEMREL_SKIP_STEPS is unset', () => {
    delete process.env.SEMREL_SKIP_STEPS
    expect(allPlugins.filter(buildSkipFilter())).toHaveLength(allPlugins.length)
  })

  it('excludes an entry whose stepId is in the skip set', () => {
    process.env.SEMREL_SKIP_STEPS = NPM
    const kept = allPlugins.filter(buildSkipFilter())
    expect(kept.some((e) => Array.isArray(e) && e[0] === NPM)).toBe(false)
  })

  it('skips a suffixed step by its full id, leaving others', () => {
    process.env.SEMREL_SKIP_STEPS = '@semantic-release/exec:build'
    const kept = allPlugins.filter(buildSkipFilter())
    expect(kept.some((e) => Array.isArray(e) && e[0] === '@semantic-release/exec')).toBe(false)
    // the npm publish step is untouched
    expect(kept.some((e) => Array.isArray(e) && e[0] === NPM)).toBe(true)
  })

  it('never drops the unskippable string entries', () => {
    process.env.SEMREL_SKIP_STEPS = '@semantic-release/commit-analyzer'
    const kept = allPlugins.filter(buildSkipFilter())
    // string entries carry no stepId, so the filter keeps them
    expect(kept).toContain('@semantic-release/commit-analyzer')
  })
})

describe('default config', () => {
  it('releases from main plus the prerelease branches', () => {
    expect(config.branches).toContain('main')
    const names = config.branches.map((b) => (typeof b === 'string' ? b : b.name))
    expect(names).toEqual(expect.arrayContaining(['main', 'pre', 'alpha', 'beta', 'rc']))
  })

  it('tags as v${version}', () => {
    expect(config.tagFormat).toBe('v${version}')
  })

  it('exposes plugins as a live, filtered getter', () => {
    expect(Array.isArray(config.plugins)).toBe(true)
    process.env.SEMREL_SKIP_STEPS = NPM
    expect(config.plugins.some((e) => Array.isArray(e) && e[0] === NPM)).toBe(false)
  })
})
