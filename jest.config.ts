import type { Config } from "jest";
// with thanks to
// https://github.com/kulshekhar/ts-jest/issues/1057#issuecomment-1068342692
const config: Config = {
    transform: { "^.+\\.ts?$": ["ts-jest", { useESM: true }] },
    verbose: true,
    testEnvironment: "node",
    testRegex: "/test/.*\\.(test|spec)?\\.(ts|tsx)$",
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
    moduleNameMapper: {
        "(.+)\\.js": "$1",
    },
    extensionsToTreatAsEsm: [".ts"],
    collectCoverage: true,
    coverageReporters: ["html", "text"],
};

export default config;
