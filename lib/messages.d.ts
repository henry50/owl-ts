import BigNumber from "bignumber.js";
import { ZKP } from "./owl_common.js";
export declare class RegistrationRequest {
    username: string;
    t: BigNumber;
    pi: BigNumber;
    T: BigNumber;
    constructor(username: string, t: BigNumber, pi: BigNumber, T: BigNumber);
    static deserialize(x: any): RegistrationRequest;
    serialize(): {
        username: string;
        t: string;
        pi: string;
        T: string;
    };
}
export declare class UserCredentials {
    X3: BigNumber;
    PI3: ZKP;
    pi: BigNumber;
    T: BigNumber;
    constructor(X3: BigNumber, PI3: ZKP, pi: BigNumber, T: BigNumber);
    static deserialize(x: any): UserCredentials;
    serialize(): {
        X3: string;
        PI3: {
            h: string;
            r: string;
        };
        pi: string;
        T: string;
    };
}
export declare class AuthInitRequest {
    X1: BigNumber;
    X2: BigNumber;
    PI1: ZKP;
    PI2: ZKP;
    constructor(X1: BigNumber, X2: BigNumber, PI1: ZKP, PI2: ZKP);
    static deserialize(x: any): AuthInitRequest;
    serialize(): {
        X1: string;
        X2: string;
        PI1: {
            h: string;
            r: string;
        };
        PI2: {
            h: string;
            r: string;
        };
    };
}
export declare class AuthInitResponse {
    X3: BigNumber;
    X4: BigNumber;
    PI3: ZKP;
    PI4: ZKP;
    beta: BigNumber;
    PIBeta: ZKP;
    constructor(X3: BigNumber, X4: BigNumber, PI3: ZKP, PI4: ZKP, beta: BigNumber, PIBeta: ZKP);
    static deserialize(x: any): AuthInitResponse;
    serialize(): {
        X3: string;
        X4: string;
        PI3: {
            h: string;
            r: string;
        };
        PI4: {
            h: string;
            r: string;
        };
        beta: string;
        PIBeta: {
            h: string;
            r: string;
        };
    };
}
export declare class AuthFinishRequest {
    alpha: BigNumber;
    PIAlpha: ZKP;
    r: BigNumber;
    constructor(alpha: BigNumber, PIAlpha: ZKP, r: BigNumber);
    static deserialize(x: any): AuthFinishRequest;
    serialize(): {
        alpha: string;
        PIAlpha: {
            h: string;
            r: string;
        };
        r: string;
    };
}
//# sourceMappingURL=messages.d.ts.map