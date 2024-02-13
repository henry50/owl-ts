import BigNumber from "bignumber.js";
import { OwlCommon, ZKP } from "./owl_common.js";
import { AuthFinishRequest, AuthInitRequest, AuthInitResponse, RegistrationRequest } from "./messages.js";
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
export declare class OwlClient extends OwlCommon {
    initValues: ClientInitVals;
    register(username: string, password: string): Promise<RegistrationRequest>;
    authInit(username: string, password: string): Promise<AuthInitRequest>;
    authFinish(request: AuthInitResponse): Promise<[BigNumber, AuthFinishRequest]>;
}
export {};
//# sourceMappingURL=owl_client.d.ts.map