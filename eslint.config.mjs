import js from '@eslint/js';
import prettierConfig from 'eslint-config-prettier';
import prettier from 'eslint-plugin-prettier';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import globals from 'globals';

export default [
  // Global ignores
  {
    ignores: [
      'dist/**',
      'build/**',
      'node_modules/**',
      '.vscode/extensions.js',
      'safari/**',
    ],
  },

  // Base configuration for JS/MJS files
  js.configs.recommended,

  // Main custom configuration
  {
    files: ['**/*.{js,mjs}'],
    plugins: {
      prettier,
      'simple-import-sort': simpleImportSort,
    },
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.webextensions,
      },
    },
    rules: {
      'prettier/prettier': 'error',
      'simple-import-sort/imports': 'error',
      'simple-import-sort/exports': 'error',
      'no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^(_|e$|event$|panel$|activeInfo$)',
          caughtErrors: 'none',
        },
      ],
    },
  },

  // Override for Node.js configuration files
  {
    files: ['eslint.config.mjs', 'scripts/**/*.mjs'],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
  },
  // Prettier config must be last
  // This turns off all rules that are unnecessary or might conflict with Prettier.
  prettierConfig,
];
