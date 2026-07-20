import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    reporters: process.env.CI ? ['dot', 'junit'] : ['verbose'],
    outputFile: { junit: 'reports/test-results.xml' },
    coverage: {
      reporter: ['text', 'cobertura'],
      reportsDirectory: 'reports'
    }
  }
})
