# owl-ts

An implementation of the Owl augmented PAKE protocol in Typescript, based on the [Owl paper](https://eprint.iacr.org/2023/768.pdf). 

## Installation
To install the package, run
```
npm install owl-ts
```

## Usage
The following sections give an overview of how the protocol works and the corresponding code. A full demonstration can be found [here](https://github.com/henry50/3rd-year-project).

### Setup
The client and server must use the same configuration of elliptic curve and server identity. The configuration object can be created as follows
```ts
import { Config, Curves } from "owl-ts";

const config: Config = {
    curve: Curves.P256,
    serverId: "example.com"
};
```

The possible values of `Curves` are `Curves.P256`, `Curves.P384` and `Curves.P521`.

This configuration can then be used to set up the client and server.
```ts
import { OwlClient, OwlServer } from "owl-ts";

const client = new OwlClient(config);
const server = new OwlServer(config);
```

### Messages
The Owl server and client use messages for input and output. Messages can be serialized to JSON with the `serialize()` method. Messages can be deserialized using the `deserialize()` method. This method takes either a JSON object or its string representation and returns a message object or a `DeserializationError` if the input was not a valid message. 

There are 6 message classes:
- `RegistrationRequest` - Contains values output by `OwlClient.register` and used by `OwlServer.register`
- `UserCredentials` - Contains user credentials to be stored permanently in the database alongside the username
- `AuthInitRequest` - Contains values output by `OwlClient.authInit` and used by `OwlServer.authInit`
- `AuthInitialValues` - Temporary values output by `OwlServer.authInit` and used by `OwlServer.authFinish` to be stored in the database alongside the username. After `OwlServer.authFinish` is complete these values can be deleted.
- `AuthInitResponse` - Contains values output by `OwlServer.authInit` and used by `OwlClient.authFinish`
- `AuthFinishRequest` - Contains values output by `OwlClient.authFinish` and used by `OwlServer.authFinish`

### Registration
Registration must be done over a secure connection such as HTTPS. 

Firstly, pass the username and password to `OwlClient.register`. This produces a `RegistrationRequest` which is sent to the server. 

```ts
const request = await client.register("username", "password");
const data = {
    username: "username",
    request: request.serialize(),
};
// send data to server
```
The server should check if the username is already in use, then use the `OwlServer.register` method to produce a `UserCredentials` object and store it in the database.
```ts
import { RegistrationRequest } from "owl-ts";

// assuming data is the JSON from the client's request
const { username, request } = data;

// check if user already exists
if (database[username]) {
    // handle taken username
}

const regRequest = RegistrationRequest.deserialize(request, config);
if (regRequest instanceof DeserializationError) {
    // handle invalid request
}

const credentials = await server.register(regRequest);

// save user record to database
database[username].credentials = credentials.serialize();
```

### Authentication
Authentication does **not** need to be done over a secure connection. It consists of four stages.

1. Use the `OwlClient.authInit` method to generate an `AuthInitRequest` and send it to the server.
    ```ts
    const request = await client.authInit("username", "password");
    const data = {
        username: "username",
        request: request.serialize(),
    };
    // send data to server
    ```
2. The server retrieves the user's credentials and passes them and the `AuthInitRequest` to `OwlServer.authInit` which returns an object of the form
    ```ts
    {
        response: AuthInitResponse;
        initial: AuthInitialValues;
    }
    ```
    `initial` must be stored in the database for `authFinish`. `response` must be sent to the client.

    ```ts
    // assuming data is the JSON from the client's request
    const { username, request } = data;

    // retrieve user credentials from database
    const user = database[username].credentials;

    // deserialize stored credentials
    const credentials = UserCredentials.deserialize(user, config);
    if (credentials instanceof DeserializationError) {
        // handle invalid credentials
    }

    // deserialize request
    const authRequest = AuthInitRequest.deserialize(request, config);
    if (authRequest instanceof DeserializationError) {
        // handle invalid request
    }

    // get initial auth values
    const authInit = await server.authInit(username, authRequest, credentials);
    if (authInit instanceof ZKPVerificationFailure) {
        // return ZKP verification error
    }
    const { initial, response } = authInit;

    // store initial values for authFinish
    database[username].initial = initial.serialize();

    // send response.serialize() to the client
    ```
3. Pass the `AuthInitResponse` to `client.authFinish`. This returns an object of the form
    ```ts
    {
        finishRequest: AuthFinishRequest;
        key: ArrayBuffer;
        kc: string;
        kcTest: string;
    }
    ```
    `finishRequest` is sent to the server, `key` is a mutually derived key which can be used for symmetric encryption and `kc` and `kcTest` are values used for explicit key confirmation as covered later.
    ```ts
    const initResponse = AuthInitResponse.deserialize(result, config);
    if (initResponse instanceof DeserializationError) {
        // handle invalid response
    }

    const finish = await client.authFinish(initResponse);
    if (finish instanceof Error) {
        // handle error
    }

    const data = {
        username: "username",
        request: finish.finishRequest.serialize(),
    };
    // send data to the server
    ```
4. The server retrieves the initial values and passes them and the `AuthFinishRequest` to the `OwlServer.authFinish` method. If successful, it returns an object of the form
    ```
    {
        key: ArrayBuffer;
        kc: string;
        kcTest: string;
    }
    ```
    where `key` is the mutually derived key and `kc` and `kcTest` are the key confirmation values. 
    ```ts
    // assuming data is the JSON from the client's request
    const { username, request } = data

    // retrieve the initial values from the database
    const initialRaw = database[username].initial;

    // deserialize initial values
    const initial = AuthInitialValues.deserialize(initialRaw, config);
    if (initial instanceof DeserializationError) {
        // handle invalid data
    }

    // deserialize request
    const finishReq = AuthFinishRequest.deserialize(request, config);
    if (finishReq instanceof DeserializationError) {
        // handle invalid request
    }

    // finish auth, determine is user is authenticated
    const loginSuccess = await server.authFinish(username, finishReq, initial);
    if (loginSuccess instanceof Error) {
        // handle authentication failure
    }
    // otherwise, authentication is successful
    ```

### Explicit key confirmation
Explicit key confirmation is an optional process which allows both parties to explicitly verify they have derived the same key before starting encrypted communications. Explicit key confirmation can be added to the protocol as follows:
1. The client sends their `kc` value alongside their `AuthFinishRequest`. The server can then verify if this matches their `kcTest`.

2. The server sends their `kc` value after successful authentication. The client can then verify if this matches their `kcTest`.

## Build and test

To build the package, run

```
npm install
npm run build
```

It will be built to the `lib` directory.

To test the code, run
```
npm test
```
