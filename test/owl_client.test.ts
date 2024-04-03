import { describe, test, expect } from "@jest/globals";
import {
    AuthInitResponse,
    Curves,
    OwlClient,
    UninitialisedClientError,
    ZKPVerificationFailure,
} from "../src";
import { p256 } from "@noble/curves/p256";

const cfg = {
    curve: Curves.P256,
    serverId: "localhost",
};

const ValidClientInitVals = {
    username: "test-user",
    t: 6788808824203659532873859407024911212674642751532147448678721490110692434648n,
    pi: 38296160450983800956335674330408354901235476184707419638658682833959284946055n,
    x1: 88428765960055500049374499658509038617327696051913034645988434195965142769335n,
    x2: 63810129032766333669478783146304794478369056180551485955106044713772747806307n,
    X1: new p256.ProjectivePoint(
        82063100358600708695485638526623028223474665268997349257074306965942067711659n,
        11951856226132846362383415853036840620204977205343638467060774177672131465056n,
        1n,
    ),
    X2: new p256.ProjectivePoint(
        73382262420471839264881685444725543709089995718064481663597682316463185981058n,
        77188699609723383123949892893465683491698061380907468202540903659089603429491n,
        1n,
    ),
    PI1: {
        h: 14284449127885680426509812123310497875427462603572988048658697220914565770534n,
        r: 50359093177489232215437646820589826202692881933585375354242843482435793144915n,
    },
    PI2: {
        h: 13729843566814840639257886187705135267753752949965924273661690592358599869994n,
        r: 105320662805994535685562179757317163521653383450764951766566795187608360909363n,
    },
};

const ValidAuthInitResponse = AuthInitResponse.deserialize(
    {
        X3: "03714e2027575e41a1758170017e8ef44b9f0815478d894f792dbead2b6e3c8ae3",
        X4: "032b16bd40c63a62b9066841bcecf3c17563881bb6791a67fd09795572704b255a",
        PI3: {
            h: "6d9c182c9ecaf2665d562f450ffa3bda6974b5036885a962126fc22dd2aafd39",
            r: "c4ec27c4dd95d97f6f824baffbd70bcea739d629f0223986bfefa0a26d7f3037",
        },
        PI4: {
            h: "ac120aa2727039d1d16402e6c6558ed75dcec13b5c30ce31f07475a76790afcc",
            r: "b5a082f5540731923de2ca3f8952e8891ea49e38c30173576899d0b2e73ce70e",
        },
        beta: "03369a667d440e4b6ee9314a98fd996dab812d1689ac2d6c8e3ba27ae082610fdd",
        PIBeta: {
            h: "a54ef7763f4ff0fbecfa8069e9f64692eef4f189a00adc12fa8cda13ae2130e0",
            r: "20f4f1b09fbf6986a42a2519f319abe95462804dab8bd18493a4b8cb4fffc395",
        },
    },
    cfg,
) as AuthInitResponse;

describe("Test Owl client", () => {
    test("Registration is successful", async () => {
        const client = new OwlClient(cfg);
        expect(
            await client.register("test-user", "secret-pass"),
        ).not.toBeInstanceOf(Error);
    });
    test("Initial authorisation is successful", async () => {
        const client = new OwlClient(cfg);
        expect(
            await client.authInit("username", "password"),
        ).not.toBeInstanceOf(Error);
    });
    test("Final authorisation is successful with valid AuthInitResponse", async () => {
        const client = new OwlClient(cfg);
        client.initValues = ValidClientInitVals; // mock successful AuthInit values
        expect(
            await client.authFinish(ValidAuthInitResponse),
        ).not.toBeInstanceOf(Error);
    });
    test("Final authorisation fails with invalid ZKP AuthInitResponse", async () => {
        const client = new OwlClient(cfg);
        client.initValues = ValidClientInitVals; // mock successful AuthInit values
        const invalid = Object.assign({}, ValidAuthInitResponse);
        invalid.X3 = invalid.X4; // X3=X4 will cause verification of PI3 to fail
        expect(await client.authFinish(invalid)).toBeInstanceOf(
            ZKPVerificationFailure,
        );
    });
    test("Final authorisation fails without initial authorisation", async () => {
        const client = new OwlClient(cfg);
        expect(await client.authFinish(ValidAuthInitResponse)).toBeInstanceOf(
            UninitialisedClientError,
        );
    });
});
