// with thanks to
// https://github.com/kulshekhar/ts-jest/issues/1057#issuecomment-1068342692
export default {
    transform: { "^.+\\.ts?$": ["ts-jest", { useESM: true }] },
    verbose: true,
    testEnvironment: "node",
    testRegex: "/test/.*\\.(test|spec)?\\.(ts|tsx)$",
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
    moduleNameMapper: {
        "(.+)\\.js": "$1",
    },
    extensionsToTreatAsEsm: [".ts"],
};
