module.exports = {
  globals: {
    "ts-jest": {
      tsconfig: "test/tsconfig.json",
    },
  },
  roots: ["<rootDir>/src", "<rootDir>/test"],
  clearMocks: true,
  transform: {
    "^.+\\.tsx?$": "ts-jest",
  },
  testRegex: "(/__tests__/.*|(\\.|/)(test|spec))\\.tsx?$",
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
};
