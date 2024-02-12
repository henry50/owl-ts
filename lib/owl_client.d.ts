import BigNumber from "bignumber.js";
import { OwlCommon, ZKP } from "./owl_common.js";
interface ClientInitVals {
    username: string;
    t: BigNumber;
    pi: BigNumber;
    x1: BigNumber;
    x2: BigNumber;
    X1: BigNumber;
    X2: BigNumber;
    PI1: ZKP;
    PI2: ZKP;
}
export declare class RegistrationRequest {
    username: string;
    t: BigNumber;
    pi: BigNumber;
    T: BigNumber;
    constructor(username: string, t: BigNumber, pi: BigNumber, T: BigNumber);
    static deserialize(x: string): RegistrationRequest;
    serialize(): string;
}
export declare class OwlClient extends OwlCommon {
    initValues: ClientInitVals;
    register(username: string, password: string): Promise<RegistrationRequest>;
    authInit(username: string, password: string): Promise<{
        X1: BigNumber;
        X2: BigNumber;
        PI1: ZKP;
        PI2: ZKP;
    }>;
    authFinish(X3: BigNumber, X4: BigNumber, PI3: ZKP, PI4: ZKP, beta: BigNumber, PIbeta: ZKP): Promise<[BigNumber, {
        alpha: BigNumber;
        PIalpha: ZKP;
        r: BigNumber;
    }]>;
}
export {};
//# sourceMappingURL=owl_client.d.ts.map