import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    include: ['server/**/*.test.ts', 'tests/**/*.test.ts'],
    testTimeout: 10_000,
  },
});
