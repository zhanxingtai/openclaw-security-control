import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    fileParallelism: false,
    include: ['**/*.test.ts'],
    exclude: ['openclaw-2026.8.2/**', 'node_modules/**', 'dist/**', 'install/**'],
  },
});
