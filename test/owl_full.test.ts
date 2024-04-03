import {
    OwlClient,
    OwlServer,
    Curves,
    Config,
    RegistrationRequest,
    DeserializationError,
    AuthInitRequest,
    ZKPVerificationFailure,
    AuthInitResponse,
    AuthFinishRequest,
    AuthenticationFailure,
    UserCredentials,
    AuthInitialValues,
    UninitialisedClientError,
} from "../src";
import { describe, test, expect } from "@jest/globals";

/**
 *  Test of the full Owl protocol implementation
 */

const cfg = {
    curve: Curves.P256,
    serverId: "localhost",
};

const database: {
    users: { [id: string]: any };
    initialValues: { [id: string]: any };
} = { users: {}, initialValues: {} };

async function registrationTest(cfg: Config) {
    const username = "test-user";
    const password = "secret-password";
    const client = new OwlClient(cfg);
    const server = new OwlServer(cfg);

    const request = await client.register(username, password);
    const jsonRequest = request.serialize();

    // client ---> username, RegistrationRequest ---> server

    const parsedRequest = RegistrationRequest.deserialize(jsonRequest, cfg);
    expect(parsedRequest).not.toBeInstanceOf(DeserializationError);
    if (parsedRequest instanceof DeserializationError) {
        throw parsedRequest;
    }
    const userCredentials = await server.register(parsedRequest);
    database.users[username] = userCredentials.serialize();
}

async function authTest(username: string, password: string, cfg: Config) {
    const client = new OwlClient(cfg);
    const server = new OwlServer(cfg);

    const initRequest = await client.authInit(username, password);
    const jsonInitRequest = initRequest.serialize();

    // client ---> username, AuthInitRequest ---> server

    const parsedInitRequest = AuthInitRequest.deserialize(jsonInitRequest, cfg);
    expect(parsedInitRequest).not.toBeInstanceOf(DeserializationError);
    if (parsedInitRequest instanceof DeserializationError) {
        throw parsedInitRequest;
    }
    const parsedCredentials = UserCredentials.deserialize(
        database.users[username],
        cfg,
    );
    expect(parsedCredentials).not.toBeInstanceOf(DeserializationError);
    if (parsedCredentials instanceof DeserializationError) {
        throw parsedCredentials;
    }
    const serverAuthInit = await server.authInit(
        username,
        parsedInitRequest,
        parsedCredentials,
    );
    expect(serverAuthInit).not.toBeInstanceOf(ZKPVerificationFailure);
    if (serverAuthInit instanceof ZKPVerificationFailure) {
        throw serverAuthInit;
    }
    database.initialValues[username] = serverAuthInit.initial.serialize();
    const initResponse = serverAuthInit.response;
    const jsonInitResponse = initResponse.serialize();

    // server ---> AuthInitResponse ---> client

    const parsedInitResponse = AuthInitResponse.deserialize(
        jsonInitResponse,
        cfg,
    );
    expect(parsedInitResponse).not.toBeInstanceOf(DeserializationError);
    if (parsedInitResponse instanceof DeserializationError) {
        throw parsedInitResponse;
    }
    const clientAuthFinish = await client.authFinish(parsedInitResponse);
    expect(clientAuthFinish).not.toBeInstanceOf(ZKPVerificationFailure);
    expect(clientAuthFinish).not.toBeInstanceOf(UninitialisedClientError);
    if (clientAuthFinish instanceof Error) {
        throw clientAuthFinish;
    }
    const clientDerivedKey = clientAuthFinish.key;
    // this is what the client sends to the server to show
    // they have derived the same key
    const clientKeyConfirmation = clientAuthFinish.kc;
    // this is what the client uses to check the key sent to
    // them by the server is the same key
    const clientKeyConfirmationTest = clientAuthFinish.kcTest;
    const jsonFinishRequest = clientAuthFinish.finishRequest.serialize();

    // client ---> username, AuthFinishRequest, kc ---> server

    const parsedFinishRequest = AuthFinishRequest.deserialize(
        jsonFinishRequest,
        cfg,
    );
    expect(parsedFinishRequest).not.toBeInstanceOf(DeserializationError);
    if (parsedFinishRequest instanceof DeserializationError) {
        throw parsedFinishRequest;
    }
    const parsedInitialValues = AuthInitialValues.deserialize(
        database.initialValues[username],
        cfg,
    );
    expect(parsedInitialValues).not.toBeInstanceOf(DeserializationError);
    if (parsedInitialValues instanceof DeserializationError) {
        throw parsedInitialValues;
    }
    const serverAuthFinish = await server.authFinish(
        username,
        parsedFinishRequest,
        parsedInitialValues,
    );
    expect(serverAuthFinish).not.toBeInstanceOf(ZKPVerificationFailure);
    if (serverAuthFinish instanceof Error) {
        throw serverAuthFinish;
    }
    // after this point the user has been authenticated successfully
    // the client and server should have derived the same keys
    const serverDerivedKey = serverAuthFinish.key;
    expect(clientDerivedKey).toStrictEqual(serverDerivedKey);

    // explicit key confirmation allows the client and server
    // to show each other they have derived the same key

    // this is optional, if one party can decrypt the other's
    // encrypted message then that implicitly shows they know the key

    const serverKeyConfirmation = serverAuthFinish.kc;
    const serverKeyConfirmationTest = serverAuthFinish.kcTest;

    // check client key confirmation
    expect(clientKeyConfirmation).toBe(serverKeyConfirmationTest);

    // server ---> success, kc ---> client

    // check server key confirmation
    expect(serverKeyConfirmation).toBe(clientKeyConfirmationTest);
}

describe("Test full protocol", () => {
    test("Registration", async () => await registrationTest(cfg));
    test("Valid login", async () =>
        expect(await authTest("test-user", "secret-password", cfg)));
    test("Invalid login", async () =>
        await expect(
            authTest("test-user", "wrong-password", cfg),
        ).rejects.toThrow(AuthenticationFailure));
});
