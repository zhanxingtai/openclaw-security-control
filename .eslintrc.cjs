module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    project: './tsconfig.json',
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
  ],
  env: {
    node: true,
    es2022: true,
  },
  rules: {
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    'no-console': 'off',
  },
  // Test files are excluded from tsconfig.json (type-aware linting cannot
  // parse them there) — vitest is their gate. Keep eslint's scope aligned
  // with tsc so `npm run lint` is CI-clean.
  ignorePatterns: ['dist/', 'install/', 'node_modules/', 'tmp/', '*.js', '**/*.test.ts'],
};
