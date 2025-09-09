module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es6: true,
    node: true
  },
  extends: 'eslint:recommended',
  globals: {
    Atomics: 'readonly',
    SharedArrayBuffer: 'readonly'
  },
  parserOptions: {
    ecmaVersion: 2018
  },
  rules: {
    // Core quality rules
    'eqeqeq': 'error',
    'no-var': 'error',
    'prefer-const': 'error',
        
    // Style (minimal)
    'indent': ['error', 2],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
        
    // Disable overly strict rules
    'no-magic-numbers': 'off',
    'no-await-in-loop': 'warn',
    'no-process-exit': 'off',
    'no-console': 'off'
  }
};
