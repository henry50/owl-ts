import BigNumber from "bignumber.js";
import { OwlCommon, ZKPVerificationFailure } from "./owl_common.js";
import { AuthInitResponse, UserCredentials } from "./messages.js";
export class OwlServer extends OwlCommon {
    initValues;
    async register(request) {
        const x3 = this.rand(BigNumber(1), this.config.q.minus(1));
        const X3 = this.config.g.pow(x3, this.config.p);
        const PI3 = await this.createZKP(x3, this.config.g, X3, this.config.serverId);
        return new UserCredentials(X3, PI3, request.pi, request.T);
    }
    async authInit(username, request, credentials) {
        const { X1, X2, PI1, PI2 } = request;
        const { X3, PI3, pi, T } = credentials;
        if (!(await this.verifyZKP(PI1, this.config.g, X1, username) &&
            await this.verifyZKP(PI2, this.config.g, X2, username))) {
            throw new ZKPVerificationFailure();
        }
        if (X2.mod(this.config.p).eq(1)) {
            throw new Error("Invalid value given for X2");
        }
        const x4 = this.rand(BigNumber(1), this.config.q.minus(1));
        const X4 = this.config.g.pow(x4, this.config.p);
        const PI4 = await this.createZKP(x4, this.config.g, X4, this.config.serverId);
        const secret = pi.times(x4);
        const betaGen = X1.times(X2).times(X3);
        const beta = betaGen.pow(secret, this.config.p);
        const PIBeta = await this.createZKP(secret, betaGen, beta, this.config.serverId);
        // keep values for authFinish (this should probably be changed to store in database)
        this.initValues = { username, T, pi, x4, X1, X2, X3, X4, beta, PI1, PI2, PI3, PIBeta };
        return new AuthInitResponse(X3, X4, PI3, PI4, beta, PIBeta);
    }
    async authFinish(request) {
        const { username, T, pi, x4, X1, X2, X3, X4, beta, PI1, PI2, PI3, PIBeta } = this.initValues;
        const { alpha, PIAlpha, r } = request;
        if (!await this.verifyZKP(PIAlpha, X1.times(X3).times(X4), alpha, username)) {
            throw new ZKPVerificationFailure();
        }
        // X2^(-x4*pi)
        const X2X4pi = this.modExp(X2, x4.times(pi).negated(), this.config.p);
        if (X2X4pi instanceof Error) {
            return false;
        }
        // K = ((alpha % p) * (X2^(-x4*pi) % p)^x4 % p
        const K = alpha.mod(this.config.p).times(X2X4pi).mod(this.config.p).pow(x4, this.config.p);
        // h = H(K||Transcript) % p
        const h = (await this.H(this.concat(K, username, X1, X2, PI1.h, PI1.r, PI2.h, PI2.r, this.config.serverId, X3, X4, PI3.h, PI3.r, beta, PIBeta.h, PIBeta.r, alpha, PIAlpha.h, PIAlpha.r)))
            .mod(this.config.p);
        // g^r % p ?= T^h % p
        const grp = this.modExp(this.config.g, r, this.config.p);
        if (grp instanceof Error) {
            return false;
        }
        const k = await this.H(K.toString());
        if (!grp.times(T.pow(h, this.config.p)).mod(this.config.p).eq(X1)) {
            return false;
        }
        return k;
    }
}
