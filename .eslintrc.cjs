module.exports = {
	root: true,

	parserOptions: {
		parser: require.resolve('@typescript-eslint/parser'),
		extraFileExtensions: ['.vue'],
	},

	env: {
		browser: false,
		node: true,
	},

	extends: [
		'standard',
		'eslint:recommended',
		'plugin:@typescript-eslint/recommended',
		'plugin:import/recommended',
		'plugin:import/typescript',
	],

	plugins: ['@typescript-eslint', 'import'],

	globals: {
		RequestInit: 'readonly',
		process: 'readonly',
		Capacitor: 'readonly',
		chrome: 'readonly',
	},

	rules: {
		// Updated indent rule with SwitchCase option
		indent: ['error', 'tab', { SwitchCase: 1 }],
		'no-mixed-spaces-and-tabs': ['error', 'smart-tabs'],
		quotes: ['warn', 'single', { avoidEscape: true }],
		semi: ['error', 'always'],
		'comma-dangle': 'off',

		'generator-star-spacing': 'off',
		'no-tabs': 'off',
		'arrow-parens': 'off',
		'one-var': 'off',
		'no-void': 'off',
		'multiline-ternary': 'off',
		camelcase: 'off',
		'new-cap': 'off',

		'prefer-promise-reject-errors': 'off',
		'@typescript-eslint/explicit-function-return-type': 'off',
		'@typescript-eslint/no-explicit-any': 'off',
		'@typescript-eslint/no-require-imports': 'off',
		'@typescript-eslint/no-empty-object-type': 'off',
		'@typescript-eslint/no-unused-vars': 'off',
		'@typescript-eslint/no-var-requires': 'off',
		'@typescript-eslint/no-use-before-define': [
			'error',
			{
				classes: false,
				functions: true,
				variables: true,
			},
		],
		'no-unused-vars': 'off',
		'no-debugger': process.env.NODE_ENV === 'production' ? 'error' : 'off',

		'space-before-function-paren': 'off',

		'import/order': [
			'error',
			{
				groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index', 'object', 'type'],
				'newlines-between': 'always',
				alphabetize: { order: 'asc', caseInsensitive: true },
			},
		],
		'import/default': 'error',
		'import/export': 'error',
		'import/extensions': 'off',
		'import/first': 'error',
		'import/named': 'off',
		'import/namespace': 'error',
		'import/exports-last': 'off',
		'import/no-cycle': 'warn',
		'import/no-useless-path-segments': 'error',
		'import/no-extraneous-dependencies': 'off',
		'import/no-self-import': 'error',
		'import/no-absolute-path': 'error',
		'import/no-named-as-default': 'error',
		'import/no-duplicates': 'error',
		'import/no-namespace': 'error',
		'import/no-deprecated': 'error',
		'import/no-internal-modules': 'off',
		'import/no-unresolved': 'off',
	},
	overrides: [
		{
			// Override for JSON files to enforce double quotes
			files: ['*.json'],
			rules: {
				quotes: ['error', 'double'],
			},
		},
	],
};
