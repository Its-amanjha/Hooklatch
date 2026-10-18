module.exports = {
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  transform: { '^.+\\.tsx?$': ['ts-jest', { useESM: true, tsconfig: { target: 'ES2022', module: 'ESNext', moduleResolution: 'Bundler', rootDir: '.', types: ['node', 'jest'], isolatedModules: true, noEmitOnError: false, strict: true, exactOptionalPropertyTypes: true, esModuleInterop: true } }] },
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: ['src/**/*.ts'],
  coverageDirectory: 'coverage',
  coverageThreshold: { global: { statements: 80, branches: 80, functions: 80, lines: 80 } }
};
