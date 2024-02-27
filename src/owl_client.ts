import { OwlCommon, Point, ZKP, ZKPVerificationFailure } from "./owl_common.js";
import {
    AuthFinishRequest,
    AuthInitRequest,
    AuthInitResponse,
    RegistrationRequest,
} from "./messages.js";

interface ClientInitVals {
    username: string;
    t: bigint;
    pi: bigint;
    x1: bigint;
    x2: bigint;
    X1: Point;
    X2: Point;
    PI1: ZKP;
    PI2: ZKP;
}

export class OwlClient extends OwlCommon {
    initValues!: ClientInitVals;
    async register(
        username: string,
        password: string,
    ): Promise<RegistrationRequest> {
        // t = H(U||w) ??
        const t = await this.H(username + password);
        // pi = H(t) ??
        const pi = await this.H(t);
        // T = g*t ??
        const T = this.G.multiply(t);
        return new RegistrationRequest(username, t, pi, T);
    }
    async authInit(
        username: string,
        password: string,
    ): Promise<AuthInitRequest> {
        // t = H(U||w) ??
        const t = await this.H(username + password);
        // pi = H(t) ??
        const pi = await this.H(t);
        // x1 = [1, n-1]
        const x1 = this.rand(1n, this.n - 1n);
        // x2 = [1, n-1]
        const x2 = this.rand(1n, this.n - 1n);
        // X1 = G * x1
        const X1 = this.G.multiply(x1);
        // X2 = G * x2
        const X2 = this.G.multiply(x2);
        // PI1 = ZKP{x1}
        const PI1 = await this.createZKP(x1, this.G, X1, username);
        // PI2 = ZKP{x2}
        const PI2 = await this.createZKP(x2, this.G, X2, username);
        // keep values for use in authFinish
        this.initValues = { username, t, pi, x1, x2, X1, X2, PI1, PI2 };
        return new AuthInitRequest(X1, X2, PI1, PI2);
    }
    async authFinish(request: AuthInitResponse): Promise<
        | {
              key: bigint;
              finishRequest: AuthFinishRequest;
          }
        | Error
    > {
        const { username, t, pi, x1, x2, X1, X2, PI1, PI2 } = this.initValues;
        const { X3, X4, PI3, PI4, beta, PIBeta } = request;
        // verify ZKPs ?? and check X4 is valid
        if (
            !(
                (
                    (await this.verifyZKP(PI3, this.G, X3, this.serverId)) &&
                    (await this.verifyZKP(PI4, this.G, X4, this.serverId)) &&
                    (await this.verifyZKP(
                        PIBeta,
                        X1.add(X2).add(X3),
                        beta,
                        this.serverId,
                    ))
                ) //&&
                //  !X4.mod(this.config.p).eq(1) ??
            )
        ) {
            return new ZKPVerificationFailure();
        }
        const secret = this.addModN(x2, pi);
        const alpha_G = X1.add(X3).add(X4);
        // alpha = (X1+X3+X4)*(x2 + pi)
        const alpha = alpha_G.multiply(secret);
        // PIalpha = ZKP{x2 + pi}
        const PIalpha = await this.createZKP(secret, alpha_G, alpha, username);
        // K = (beta-(X4*(x2 + pi)))*x2 ?? % p
        const K = beta.subtract(X4.multiply(secret)).multiply(x2);
        // h = H(K||Transcript) ?? % p
        const h = await this.H(
            K,
            username,
            X1,
            X2,
            PI1.V,
            PI1.r,
            PI2.V,
            PI2.r,
            this.serverId,
            X3,
            X4,
            PI3.V,
            PI3.r,
            beta,
            PIBeta.V,
            PIBeta.r,
            alpha,
            PIalpha.V,
            PIalpha.r,
        );
        // r = (x1 - (t * h)) ?? % q
        const r = this.addModN(x1, -(t * h)); //% this.n
        // k = H(K) (mutually derived key)
        const k = await this.H(K.toRawBytes());
        return {
            key: k,
            finishRequest: new AuthFinishRequest(alpha, PIalpha, r),
        };
    }
}
