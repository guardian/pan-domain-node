/** @type {import('jest').Config} */
module.exports = {
  "roots": [
    "<rootDir>/src",
    "<rootDir>/test"
  ],
  "clearMocks": true,
  "transform": {
    "^.+\\.tsx?$": ["ts-jest", {
      useESM: true
    }]
  },
  "testRegex": "(/__tests__/.*|(\\.|/)(test|spec))\\.tsx?$",
  "moduleFileExtensions": [
    "ts",
    "tsx",
    "js",
    "jsx",
    "json",
    "node"
  ],
  "testEnvironment": "node",
  "verbose": true
}
