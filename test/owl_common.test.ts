import { OwlCommon, Curves } from "../src/owl_common";
import { p256 } from "@noble/curves/p256";
import { describe, test, expect } from "@jest/globals";

class TestCommon extends OwlCommon {}
const common = new TestCommon({
    curve: Curves.P256,
    serverId: "localhost",
});

describe("Testing modulus function", () => {
    test("Test positive mod positive", () => {
        expect(common.modN(2n * common.n + 104n)).toBe(104n);
    });
    test("Test negative mod positive", () => {
        expect(common.modN(-2n * common.n + 104n)).toBe(104n);
    });
});

// concatToBytes is implicitly tested by these tests
describe("Testing hash function", () => {
    test("Hash of string", async () => {
        const hash = await common.H("test");
        expect(hash).toBe(
            BigInt(
                "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            ),
        );
    });
    test("Hash of bigint", async () => {
        const hash = await common.H(100n);
        expect(hash).toBe(
            BigInt(
                "0x18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
            ),
        );
    });
    test("Hash of Point", async () => {
        const point = new p256.ProjectivePoint(
            p256.CURVE.Gx,
            p256.CURVE.Gy,
            1n,
        );
        const hash = await common.H(point);
        expect(hash).toBe(
            BigInt(
                "0x5baff89de7de5c1d7b6193a1567ceeeb397cbda88f03f725c8de328591bfc194",
            ),
        );
    });
    test("Hash of Uint8Array", async () => {
        const hash = await common.H(new Uint8Array([1, 2, 3, 4]));
        expect(hash).toBe(
            BigInt(
                "0x9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
            ),
        );
    });
    test("Hash of nothing", async () => {
        const hash = await common.H(new Uint8Array());
        expect(hash).toBe(
            BigInt(
                "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        );
    });
    test("Hash of mixed types", async () => {
        const point = new p256.ProjectivePoint(
            p256.CURVE.Gx,
            p256.CURVE.Gy,
            1n,
        );
        const hash = await common.H(
            "string",
            point,
            12345n,
            new Uint8Array([2, 4, 6, 8, 10]),
        );
        expect(hash).toBe(
            BigInt(
                "0x176cbf98027f5436b28fa33c76aef31683d5d4ad0e8aee65427b37c7f3971f92",
            ),
        );
    });
    test("Hash of invalid type throws an error", async () => {
        // @ts-expect-error
        await expect(common.H({ invalid: "object" })).rejects.toThrow(
            "Unsupported type in concatToBytes",
        );
    });
});

describe("Testing ZKP creation and verification", () => {
    const x = common.rand(1n, common.n - 1n);
    const X = common.G.multiply(x);
    test("ZKP created successfully", async () => {
        expect(await common.createZKP(x, common.G, X, "prover-identity"))
            .resolves;
    });
    test("ZKP verifies successfully", async () => {
        const zkp = await common.createZKP(x, common.G, X, "prover-identity");
        expect(
            await common.verifyZKP(zkp, common.G, X, "prover-identity"),
        ).toBe(true);
    });
    test("ZKP verification fails for invalid ZKP", async () => {
        const x2 = common.rand(1n, common.n - 1n);
        const zkp = await common.createZKP(x2, common.G, X, "prover-identity");
        expect(
            await common.verifyZKP(zkp, common.G, X, "prover-identity"),
        ).toBe(false);
    });
    test("ZKP verification fails for invalid public key", async () => {
        const zkp = await common.createZKP(x, common.G, X, "prover-identity");
        const invalidX = new p256.ProjectivePoint(0n, 0n, 0n);
        expect(
            await common.verifyZKP(zkp, common.G, invalidX, "prover-identity"),
        ).toBe(false);
    });
    test("ZKP verification fails for incorrect prover identity", async () => {
        const zkp = await common.createZKP(x, common.G, X, "prover-identity");
        expect(
            await common.verifyZKP(zkp, common.G, X, "not-the-original-prover"),
        ).toBe(false);
    });
    test("ZKP verification fails for incorrect generator", async () => {
        const zkp = await common.createZKP(x, common.G, X, "prover-identity");
        expect(await common.verifyZKP(zkp, X, X, "prover-identity")).toBe(
            false,
        );
    });
});
