import { describe, expect, test } from "@jest/globals";
import { AuthFinishRequest, Curves, DeserializationError } from "../src";

const cfg = {
    curve: Curves.P256,
    serverId: "localhost",
};

const ValidAuthFinishRequestJSON = {
    alpha: "02dba39b27575d602ed582ad6f377fb115863a151f987d2fff2329379af4cada60",
    PIAlpha: {
        h: "75a313af15f57d333f66cea6aa5055550929e1081f0b557b7a59fe63cbf55c31",
        r: "1563f71238288125a5ac1cff608b0795572e2a979cf788b7bd2e069ba9e6dde",
    },
    r: "46493c34d2599be47044b7b1917b4ec645547b9af3e761546e5c1fea6fc25434",
};
const ValidAuthFinishRequestString = JSON.stringify(ValidAuthFinishRequestJSON);

// These tests focus on AuthFinishRequest because it has one of each type of data
// Therefore, these tests should cover all other message classes as they are all generated the same way
describe("Test message deserialization", () => {
    test("Valid JSON is parsed correctly", () => {
        expect(
            AuthFinishRequest.deserialize(ValidAuthFinishRequestJSON, cfg),
        ).not.toBeInstanceOf(DeserializationError);
    });
    test("Valid string of JSON is parsed correctly", () => {
        expect(
            AuthFinishRequest.deserialize(ValidAuthFinishRequestString, cfg),
        ).not.toBeInstanceOf(DeserializationError);
    });
    test("Object with none of the required properties cannot be parsed", () => {
        expect(
            AuthFinishRequest.deserialize({ not: "valid" }, cfg),
        ).toBeInstanceOf(DeserializationError);
    });
    test("Object with some of the required properties cannot be parsed", () => {
        expect(
            AuthFinishRequest.deserialize(
                {
                    alpha: ValidAuthFinishRequestJSON.alpha,
                    other: false,
                },
                cfg,
            ),
        );
    });
    test("Undefined cannot be parsed", () => {
        expect(AuthFinishRequest.deserialize(undefined, cfg)).toBeInstanceOf(
            DeserializationError,
        );
    });
    test("Null cannot be parsed", () => {
        expect(AuthFinishRequest.deserialize(null, cfg)).toBeInstanceOf(
            DeserializationError,
        );
    });
    test("Object with invalid Point cannot be parsed", () => {
        const invalid = JSON.parse(ValidAuthFinishRequestString);
        invalid.alpha = "not a point";
        expect(AuthFinishRequest.deserialize(invalid, cfg)).toBeInstanceOf(
            DeserializationError,
        );
    });
    test("Object with invalid ZKP cannot be parsed", () => {
        const invalid = JSON.parse(ValidAuthFinishRequestString);
        invalid.PIAlpha = "not a zkp";
        expect(AuthFinishRequest.deserialize(invalid, cfg)).toBeInstanceOf(
            DeserializationError,
        );
    });
    test("Object with invalid ZKP h value cannot be parsed", () => {
        const invalid = JSON.parse(ValidAuthFinishRequestString);
        invalid.PIAlpha.h = "not a valid h value";
        expect(AuthFinishRequest.deserialize(invalid, cfg)).toBeInstanceOf(
            DeserializationError,
        );
    });
    test("Object with invalid ZKP r value cannot be parsed", () => {
        const invalid = JSON.parse(ValidAuthFinishRequestString);
        invalid.PIAlpha.r = "not a valid r value";
        expect(AuthFinishRequest.deserialize(invalid, cfg)).toBeInstanceOf(
            DeserializationError,
        );
    });
    test("Object with invalid bigint cannot be parsed", () => {
        const invalid = JSON.parse(ValidAuthFinishRequestString);
        invalid.r = "not a valid bigint";
        expect(AuthFinishRequest.deserialize(invalid, cfg)).toBeInstanceOf(
            DeserializationError,
        );
    });
});
