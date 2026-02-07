import CodeX from 'eslint-config-codex';
import { plugin as TsPlugin, parser as TsParser } from 'typescript-eslint';
import path from 'path';
import { fileURLToPath } from 'url';
import EslintTestsConfig from './eslint.config.test.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default [
  ...CodeX,
  ...EslintTestsConfig,
  /* n/no-missing-import resolves from file dir and misses workspace deps; TypeScript validates imports via projectService */
  {
    name: 'codex-lib-ts-workspace-resolve',
    files: ['packages/**/*.ts'],
    rules: {
      'n/no-missing-import': 'off',
    },
  },
  {
    name: 'codex-lib-ts',
    ignores: [
      // 'eslint.config.mjs',
    ],
    plugins: {
      '@typescript-eslint': TsPlugin,
    },

    /**
     * This are the options for typescript files
     */
    languageOptions: {
      parser: TsParser,
      parserOptions: {
        project: path.join(__dirname, 'tsconfig.eslint.json'),
        tsconfigRootDir: __dirname,
        sourceType: 'module',
      },
    },

    rules: {
    },
  },
];
