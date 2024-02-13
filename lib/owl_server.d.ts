import BigNumber from "bignumber.js";
import { OwlCommon, ZKP } from "./owl_common.js";
import { AuthFinishRequest, AuthInitRequest, AuthInitResponse, RegistrationRequest, UserCredentials } from "./messages.js";
interface ServerInitVals {
    username: string;
    T: BigNumber;
    pi: BigNumber;
    x4: BigNumber;
    X1: BigNumber;
    X2: BigNumber;
    X3: BigNumber;
    X4: BigNumber;
    beta: BigNumber;
    PI1: ZKP;
    PI2: ZKP;
    PI3: ZKP;
    PIBeta: ZKP;
}
export declare class OwlServer extends OwlCommon {
    initValues: ServerInitVals;
    register(request: RegistrationRequest): Promise<UserCredentials>;
    authInit(username: string, request: AuthInitRequest, credentials: UserCredentials): Promise<AuthInitResponse>;
    authFinish(request: AuthFinishRequest): Promise<BigNumber | false>;
}
export {};
//# sourceMappingURL=owl_server.d.ts.map