import BigNumber from "bignumber.js";
import { OwlCommon, ZKP, ZKPVerificationFailure } from "./owl_common.js"
import { AuthFinishRequest, AuthInitRequest, AuthInitResponse, RegistrationRequest } from "./messages.js";

interface ClientInitVals{
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

export class OwlClient extends OwlCommon {
    initValues!: ClientInitVals;
    async register(username: string, password: string): Promise<RegistrationRequest> {
        // t = H(U||w) % q
        const t = (await this.H(username + password)).mod(this.config.q);
        // pi = H(t) % q
        const pi = (await this.H(t.toString(10))).mod(this.config.q);
        // T = g^t % p
        const T = this.config.g.pow(t, this.config.p);
        return new RegistrationRequest(username, t, pi, T);
    }
    async authInit(username: string, password: string): Promise<AuthInitRequest> {
        // t = H(U||w) % q
        const t = (await this.H(username + password)).mod(this.config.q);
        // pi = H(t) % q
        const pi = (await this.H(t.toString(10))).mod(this.config.q);
        // x1 = [0, q-1]
        const x1 = this.rand(BigNumber(0), this.config.q.minus(1));
        // x2 = [1, q-1]
        const x2 = this.rand(BigNumber(1), this.config.q.minus(1));
        // X1 = g^x1 % p
        const X1 = this.config.g.pow(x1, this.config.p);
        // X2 = g^x2 % p
        const X2 = this.config.g.pow(x2, this.config.p);
        // PI1 = ZKP{x1}
        const PI1 = await this.createZKP(x1, this.config.g, X1, username);
        // PI2 = ZKP{x2}
        const PI2 = await this.createZKP(x2, this.config.g, X2, username);
        // keep values for use in authFinish
        this.initValues = {username, t, pi, x1, x2, X1, X2, PI1, PI2};
        return new AuthInitRequest(X1, X2, PI1, PI2);
    }
    async authFinish(request: AuthInitResponse): Promise<[BigNumber, AuthFinishRequest]> {
        const {username, t, pi, x1, x2, X1, X2, PI1, PI2} = this.initValues;
        const {X3, X4, PI3, PI4, beta, PIBeta} = request;
        // verify ZKPs and check X4 is valid
        if(!(await this.verifyZKP(PI3, this.config.g, X3, this.config.serverId) &&
             await this.verifyZKP(PI4, this.config.g, X4, this.config.serverId) &&
             await this.verifyZKP(PIBeta, X1.times(X2).times(X3), beta, this.config.serverId) &&
             !X4.mod(this.config.p).eq(1)
        )){
            // this should be an error
            throw new ZKPVerificationFailure();
        }
        const alpha_g = X1.times(X3).times(X4);
        // alpha = X1X3X4^(x2 * pi) % p
        const alpha = alpha_g.pow(x2.times(pi), this.config.p);
        // PIalpha = ZKP{x2 * pi}
        const PIalpha = await this.createZKP(x2.times(pi), alpha_g, alpha, username);
        // K = (beta/(X4^(x2 * pi)))^x2 % p
        // or equivalently
        // K = (((beta % p) * ((X4^-x2*pi) % p)) % p)^x2 % p
        const X4x2pi = this.modExp(X4, x2.negated().times(pi), this.config.p);
        if(X4x2pi instanceof Error){
            throw X4x2pi;
        }
        const K = beta.mod(this.config.p)
                  .times(X4x2pi)
                  .mod(this.config.p).pow(x2, this.config.p);                 
        // h = H(K||Transcript) % p
        const h = (await this.H(this.concat(K, username, X1, X2, PI1.h, PI1.r, PI2.h, PI2.r, this.config.serverId,
            X3, X4, PI3.h, PI3.r, beta, PIBeta.h, PIBeta.r, alpha, PIalpha.h, PIalpha.r)))
            .mod(this.config.p);
        // r = (x1 - t * h) % q
        const r = x1.minus(t.times(h)).mod(this.config.q);
        // k = H(K) (mutually derived key)
        const k = await this.H(K.toString());
        return [k, new AuthFinishRequest(alpha, PIalpha, r)]
    }
}