import js from '@eslint/js';
import _import from 'eslint-plugin-import';
import eslintPrettierRecommended from 'eslint-plugin-prettier/recommended';
import unicorn from 'eslint-plugin-unicorn';
import tseslint from 'typescript-eslint';

/* eslint-disable */

export default tseslint.config(
    { ignores: ['lib', 'eslint.config.mjs'] },
    js.configs.all,
    ...tseslint.configs.all,
    _import.flatConfigs.recommended,
    _import.flatConfigs.typescript,
    eslintPrettierRecommended,
    unicorn.configs['flat/all'],
    {
        languageOptions: {
            ecmaVersion: 2025,
            sourceType: 'module',

            parserOptions: { project: ['./tsconfig.json'] },
        },

        settings: {
            'import/resolver': { typescript: true, node: true },
        },

        rules: {
            'arrow-body-style': 'off',
            camelcase: 'off',
            'class-methods-use-this': 'off',
            'max-len': ['error', 200],
            'eol-last': 'off',
            eqeqeq: ['error', 'always'],
            'linebreak-style': 'off',
            'no-underscore-dangle': 'off',

            'no-restricted-imports': [
                'error',
                {
                    paths: [
                        {
                            name: 'lodash',
                            message: 'Only submodule imports are permitted.',
                        },
                        {
                            name: 'react-redux',
                            message: 'Only import the hooks from store.ts to avoid store poisoning',
                        },
                    ],
                },
            ],

            'no-inline-comments': [
                'error',
                {
                    ignorePattern: 'webpack.*?:\\s.+',
                },
            ],

            'sort-imports': [
                'error',
                {
                    ignoreCase: true,
                    ignoreDeclarationSort: true,
                },
            ],

            'sort-keys': 'off',
            'no-warning-comments': 'off',
            'func-style': 'off',
            'no-ternary': 'off',
            'id-length': 'off',
            'default-case': 'off',
            'consistent-return': 'off',
            'max-lines-per-function': ['error', 250],
            complexity: ['error', 20],
            'no-undefined': 'off',
            'no-plusplus': 'off',
            'no-param-reassign': 'off',
            'no-continue': 'off',
            'max-statements': ['error', 150],
            'max-lines': ['error', 1000],
            'max-classes-per-file': ['error', 10],
            'max-params': 'off',
            'init-declarations': 'off',
            'require-unicode-regexp': 'off',
            'prefer-named-capture-group': 'off',

            'no-void': [
                'error',
                {
                    allowAsStatement: true,
                },
            ],

            'spaced-comment': [
                'error',
                'always',
                {
                    markers: ['/'],
                },
            ],

            'capitalized-comments': 'off',
            'object-curly-newline': 'off',
            'one-var-declaration-per-line': 'error',

            'no-implicit-coercion': [
                2,
                {
                    allow: ['!!'],
                },
            ],

            'one-var': ['error', 'never'],
            'padded-blocks': 'off',
            'prefer-arrow-callback': 'error',
            'prefer-const': 'error',
            'prefer-destructuring': 'error',
            'import/export': 'error',
            'import/no-default-export': 'error',

            'import/extensions': [
                'error',
                {
                    pattern: {
                        scss: 'always',
                        otf: 'always',
                    },
                },
            ],

            'import/no-duplicates': 'error',
            'import/no-dynamic-require': 'error',
            'import/no-extraneous-dependencies': 'error',
            'import/no-unresolved': 'error',

            'import/no-unused-modules': [
                'error',
                {
                    unusedExports: true,
                },
            ],

            'import/order': [
                'error',
                {
                    alphabetize: {
                        order: 'asc',
                    },

                    'newlines-between': 'never',
                },
            ],

            'prettier/prettier': 'error',

            'no-else-return': [
                'error',
                {
                    allowElseIf: false,
                },
            ],

            '@typescript-eslint/naming-convention': 'off',
            '@typescript-eslint/no-type-alias': 'off',
            '@typescript-eslint/no-parameter-properties': 'off',
            '@typescript-eslint/strict-boolean-expressions': 'off',
            '@typescript-eslint/lines-between-class-members': 'off',
            '@typescript-eslint/prefer-enum-initializers': 'off',

            '@typescript-eslint/max-params': [
                'error',
                {
                    max: 6,
                },
            ],

            '@typescript-eslint/prefer-readonly-parameter-types': [
                'off',
                {
                    ignoreInferredTypes: true,
                },
            ],

            '@typescript-eslint/explicit-function-return-type': 'off',
            '@typescript-eslint/no-magic-numbers': 'off',
            '@typescript-eslint/consistent-type-imports': 'off',
            '@typescript-eslint/sort-type-constituents': 'error',
            '@typescript-eslint/no-non-null-assertion': 'off',
            '@typescript-eslint/init-declarations': 'off',
            '@typescript-eslint/no-use-before-define': 'off',
            '@typescript-eslint/method-signature-style': 'off',

            '@typescript-eslint/ban-ts-comment': [
                'error',
                {
                    'ts-expect-error': true,
                    'ts-ignore': true,
                    'ts-nocheck': true,
                    'ts-check': true,
                },
            ],

            '@typescript-eslint/member-ordering': 'error',

            '@typescript-eslint/no-shadow': [
                'error',
                {
                    ignoreTypeValueShadow: true,
                },
            ],

            '@typescript-eslint/no-explicit-any': [
                'error',
                {
                    ignoreRestArgs: true,
                },
            ],

            '@typescript-eslint/explicit-module-boundary-types': 'error',

            '@typescript-eslint/no-unnecessary-condition': [
                'error',
                {
                    allowConstantLoopConditions: true,
                },
            ],

            '@typescript-eslint/no-unsafe-assignment': 'error',
            '@typescript-eslint/no-unsafe-call': 'error',
            '@typescript-eslint/no-unsafe-member-access': 'error',
            '@typescript-eslint/no-unsafe-return': 'error',
            '@typescript-eslint/no-unnecessary-type-assertion': 'error',
            '@typescript-eslint/restrict-template-expressions': 'error',
            '@typescript-eslint/no-unsafe-argument': 'error',
            '@typescript-eslint/restrict-plus-operands': 'error',

            '@typescript-eslint/parameter-properties': [
                'error',
                {
                    prefer: 'parameter-property',
                },
            ],

            '@typescript-eslint/use-unknown-in-catch-callback-variable': 'off',
            'unicorn/prevent-abbreviations': 'off',
            'unicorn/no-await-expression-member': 'off',
            'unicorn/filename-case': 'off',
            'unicorn/number-literal-case': 'off',
            'unicorn/explicit-length-check': 'off',
            'unicorn/no-array-callback-reference': 'off',
            'unicorn/prefer-query-selector': 'off',
            'unicorn/no-array-reduce': 'off',
            'unicorn/prefer-spread': 'off',
            'unicorn/no-useless-undefined': 'off',
            'unicorn/no-new-array': 'off',
            'unicorn/no-document-cookie': 'error',
            'unicorn/no-null': 'off',
            'unicorn/custom-error-definition': 'error',
            'unicorn/no-unsafe-regex': 'error',
            'unicorn/switch-case-braces': 'off',
            'unicorn/no-keyword-prefix': 'off',
            'unicorn/no-process-exit': 'off',
            'no-bitwise': 'off',
        },
    },
);
