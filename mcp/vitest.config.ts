import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 10_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
      // server.ts = bootstrap, registerAll.ts = side-effect import list only.
      exclude: ['src/**/*.d.ts', 'src/server.ts', 'src/registerAll.ts'],
      // Floors set just below current (73/68/79/73). Raise as the suite grows;
      // CI fails if coverage regresses below these.
      thresholds: {
        statements: 70,
        branches: 62,
        functions: 72,
        lines: 70,
      },
    },
  },
});
