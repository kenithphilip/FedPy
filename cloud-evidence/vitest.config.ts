import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    include: ['tests/**/*.test.ts', 'core/**/*.test.ts', 'providers/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      include: ['core/**/*.ts', 'providers/**/*.ts'],
      exclude: ['**/*.test.ts', 'core/auth/**', 'core/detect/third-party-tools.ts'],
      thresholds: {
        // Aspirational; tighten as test coverage grows
        statements: 30,
        branches: 30,
        functions: 30,
        lines: 30,
      },
    },
    testTimeout: 10_000,
  },
});
