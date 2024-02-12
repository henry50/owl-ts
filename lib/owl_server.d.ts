import BigNumber from "bignumber.js";
import { OwlCommon, ZKP } from "./owl_common.js";
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
    register(): Promise<{
        X3: BigNumber;
        PI3: {
            h: BigNumber;
            r: BigNumber;
        };
    }>;
    authInit(username: string, pi: BigNumber, T: BigNumber, X1: BigNumber, X2: BigNumber, X3: BigNumber, PI1: ZKP, PI2: ZKP, PI3: ZKP): Promise<{
        X4: BigNumber;
        PI4: ZKP;
        beta: BigNumber;
        PIBeta: ZKP;
    }>;
    authFinish(alpha: BigNumber, PIAlpha: ZKP, r: BigNumber): Promise<BigNumber | false>;
}
export {};
//# sourceMappingURL=owl_server.d.ts.map