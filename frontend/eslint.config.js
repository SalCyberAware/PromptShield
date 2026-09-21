import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{js,jsx}'],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parserOptions: {
        ecmaVersion: 'latest',
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    rules: {
      // No varsIgnorePattern: ESLint 10 treats a JSX element as an ordinary
      // reference to the variable in scope, so a component used only in JSX is
      // seen as used without help. The '^[A-Z_]' exemption that used to be
      // needed for that now only hides genuinely unused capitalised bindings.
      'no-unused-vars': ['error'],
    },
  },
  {
    // vite.config.js runs in Node, not the browser: the build-commit plugin
    // reads process.env. Without this it trips no-undef under browser globals.
    files: ['vite.config.js'],
    languageOptions: { globals: globals.node },
  },
])
