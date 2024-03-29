import { describe, test, expect } from "@jest/globals";
import {
    AuthFinishRequest,
    AuthInitRequest,
    AuthInitialValues,
    AuthenticationFailure,
    Curves,
    OwlServer,
    RegistrationRequest,
    UserCredentials,
    ZKPVerificationFailure,
} from "../src";

const cfg = {
    curve: Curves.P256,
    serverId: "localhost",
};

// these messages were created using username "test-user" and password "secret-password"
const ValidRegistrationRequest = RegistrationRequest.deserialize(
    {
        pi: "1f83b9c6ebb44c61086c70100f53447e91d7a270eab4b015d1b1aa84f1024f36",
        T: "03453f34e9e7a1ea038aefb0b01b7d28dd4b47c4d235cbdce7c9bc22ed39e3e04f",
    },
    cfg,
) as RegistrationRequest;

const ValidUserCredentials = UserCredentials.deserialize(
    {
        X3: "02f757e86b5ee6c67ac55a80181f0514be2ad134569b35c0c6cacb2157a6e056c8",
        PI3: {
            h: "f206afbb4e06952057c439130db8ee63823ea77b8d3d188845e92479833ab140",
            r: "9f0db7003eced846f7d0e995f72cb48a55594ffcaa4f949425999ed2555785f9",
        },
        pi: "1f83b9c6ebb44c61086c70100f53447e91d7a270eab4b015d1b1aa84f1024f36",
        T: "03453f34e9e7a1ea038aefb0b01b7d28dd4b47c4d235cbdce7c9bc22ed39e3e04f",
    },
    cfg,
) as UserCredentials;

const ValidAuthInitRequest = AuthInitRequest.deserialize(
    {
        X1: "025cdcf902c12b2755f4895ea55fc9aa19952504528798e822c54a9f71613469bc",
        X2: "036b44cf86f63898e72fe9604b238575a30a9237d5ee76ac681279edc9581aaf78",
        PI1: {
            h: "32999018367d526a60f5974deea1ee18279842224cc381a17c2a0cb9c6783761",
            r: "7315a7291878b99fd32ecb0e7f9434e5a7978e3e907f4a78ae0584eeeafca259",
        },
        PI2: {
            h: "7184e800951940e0b70b2f5a3cb6223261eeac1e313204609525551c1f9cb6ed",
            r: "ebca41cdef9baf652357e5f5bebc89dbbf5cd87e2de3d2df600b14732f64bfba",
        },
    },
    cfg,
) as AuthInitRequest;

const ValidAuthInitialValues = AuthInitialValues.deserialize(
    {
        T: "03453f34e9e7a1ea038aefb0b01b7d28dd4b47c4d235cbdce7c9bc22ed39e3e04f",
        pi: "1f83b9c6ebb44c61086c70100f53447e91d7a270eab4b015d1b1aa84f1024f36",
        x4: "77eb8f94306eea0642ec4129eae10446041eb0d96788d67828957c68a97238f7",
        X1: "025cdcf902c12b2755f4895ea55fc9aa19952504528798e822c54a9f71613469bc",
        X2: "036b44cf86f63898e72fe9604b238575a30a9237d5ee76ac681279edc9581aaf78",
        X3: "02f757e86b5ee6c67ac55a80181f0514be2ad134569b35c0c6cacb2157a6e056c8",
        X4: "030b05fe9c94d0e411c13c691096b43c405d6f956f821983c232baf2515e751516",
        beta: "0392a0e9005acc24c0782bf281decc18dda8367b043dc8ebbf0ea8279c0a1ab454",
        PI1: {
            h: "32999018367d526a60f5974deea1ee18279842224cc381a17c2a0cb9c6783761",
            r: "7315a7291878b99fd32ecb0e7f9434e5a7978e3e907f4a78ae0584eeeafca259",
        },
        PI2: {
            h: "7184e800951940e0b70b2f5a3cb6223261eeac1e313204609525551c1f9cb6ed",
            r: "ebca41cdef9baf652357e5f5bebc89dbbf5cd87e2de3d2df600b14732f64bfba",
        },
        PI3: {
            h: "f206afbb4e06952057c439130db8ee63823ea77b8d3d188845e92479833ab140",
            r: "9f0db7003eced846f7d0e995f72cb48a55594ffcaa4f949425999ed2555785f9",
        },
        PIBeta: {
            h: "b0be67e92553d95aa8e9acba6308bfc319ba15c290e879eee4b16c78ad59c4e2",
            r: "ccda0a86ce12d68c3f1330a3bde539bc86f70ebab4f60c2e4d609715526f0d42",
        },
    },
    cfg,
) as AuthInitialValues;

const ValidAuthFinishRequest = AuthFinishRequest.deserialize(
    {
        alpha: "02dba39b27575d602ed582ad6f377fb115863a151f987d2fff2329379af4cada60",
        PIAlpha: {
            h: "75a313af15f57d333f66cea6aa5055550929e1081f0b557b7a59fe63cbf55c31",
            r: "1563f71238288125a5ac1cff608b0795572e2a979cf788b7bd2e069ba9e6dde",
        },
        r: "46493c34d2599be47044b7b1917b4ec645547b9af3e761546e5c1fea6fc25434",
    },
    cfg,
) as AuthFinishRequest;

describe("Test Owl server", () => {
    const server = new OwlServer(cfg);
    test("Registration is successful", async () => {
        expect(
            await server.register(ValidRegistrationRequest),
        ).not.toBeInstanceOf(Error);
    });
    test("Initial authorisation is successful with valid inputs", async () => {
        expect(
            await server.authInit(
                "test-user",
                ValidAuthInitRequest,
                ValidUserCredentials,
            ),
        ).not.toBeInstanceOf(Error);
    });
    test("Initial authorisation fails with incorrect username", async () => {
        expect(
            await server.authInit(
                "wrong-username",
                ValidAuthInitRequest,
                ValidUserCredentials,
            ),
        ).toBeInstanceOf(ZKPVerificationFailure);
    });
    test("Initial authorisation fails with invalid AuthInitRequest", async () => {
        const invalid = Object.assign({}, ValidAuthInitRequest);
        invalid.X1 = invalid.X2;
        expect(
            await server.authInit("test-user", invalid, ValidUserCredentials),
        ).toBeInstanceOf(ZKPVerificationFailure);
    });
    test("Final authorisation is successful with valid inputs", async () => {
        expect(
            await server.authFinish(
                "test-user",
                ValidAuthFinishRequest,
                ValidAuthInitialValues,
            ),
        ).not.toBeInstanceOf(Error);
    });
    test("Final authorisation fails when incorrect password is used", async () => {
        const invalid = Object.assign({}, ValidAuthFinishRequest);
        invalid.r = invalid.PIAlpha.r;
        expect(
            await server.authFinish(
                "test-user",
                invalid,
                ValidAuthInitialValues,
            ),
        ).toBeInstanceOf(AuthenticationFailure);
    });
    test("Final authorisation fails with incorrect username", async () => {
        expect(
            await server.authFinish(
                "wrong-user",
                ValidAuthFinishRequest,
                ValidAuthInitialValues,
            ),
        ).toBeInstanceOf(ZKPVerificationFailure);
    });
    test("Final authorisation fails with invalid AuthFinishRequest", async () => {
        const invalid = Object.assign({}, ValidAuthFinishRequest);
        invalid.PIAlpha = ValidAuthInitRequest.PI1;
        expect(
            await server.authFinish(
                "test-user",
                invalid,
                ValidAuthInitialValues,
            ),
        ).toBeInstanceOf(ZKPVerificationFailure);
    });
    test("Final authorisation ZKP verification fails with invalid X1, X3 or X4 AuthInitialValues", async () => {
        const invalid = Object.assign({}, ValidAuthInitialValues);
        invalid.X1 = invalid.X3;
        expect(
            await server.authFinish(
                "test-user",
                ValidAuthFinishRequest,
                invalid,
            ),
        ).toBeInstanceOf(ZKPVerificationFailure);
    });
    test("Final authorisation authentication fails with other invalid AuthInitialValues", async () => {
        const invalid = Object.assign({}, ValidAuthInitialValues);
        invalid.PI1 = invalid.PI2;
        expect(
            await server.authFinish(
                "test-user",
                ValidAuthFinishRequest,
                invalid,
            ),
        ).toBeInstanceOf(AuthenticationFailure);
    });
});
