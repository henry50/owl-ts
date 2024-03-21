import {
    AuthenticationFailure,
    OwlCommon,
    ZKPVerificationFailure,
} from "./owl_common.js";
import {
    AuthFinishRequest,
    AuthInitRequest,
    AuthInitResponse,
    AuthInitialValues,
    RegistrationRequest,
    UserCredentials,
} from "./messages.js";

export class OwlServer extends OwlCommon {
    async register(request: RegistrationRequest) {
        const { pi, T } = request;
        const x3 = this.rand(1n, this.n - 1n);
        const X3 = this.G.multiply(x3);
        const PI3 = await this.createZKP(x3, this.G, X3, this.serverId);
        return new UserCredentials(X3, PI3, pi, T);
    }
    async authInit(
        username: string,
        request: AuthInitRequest,
        credentials: UserCredentials,
    ): Promise<
        | {
              response: AuthInitResponse;
              initial: AuthInitialValues;
          }
        | ZKPVerificationFailure
    > {
        const { X1, X2, PI1, PI2 } = request;
        const { X3, PI3, pi, T } = credentials;
        // verify ZKPs
        if (
            !(await this.verifyZKP(PI1, this.G, X1, username)) ||
            !(await this.verifyZKP(PI2, this.G, X2, username))
        ) {
            return new ZKPVerificationFailure();
        }
        // x4 = [1, n-1]
        const x4 = this.rand(1n, this.n - 1n);
        // X4 = G * x4
        const X4 = this.G.multiply(x4);
        // PI4 = ZKP{x4}
        const PI4 = await this.createZKP(x4, this.G, X4, this.serverId);
        const secret = this.modN(x4 * pi);
        const beta_G = X1.add(X2).add(X3);
        // beta = (X1+X2+X3) * (pi * x4)
        const beta = beta_G.multiply(secret);
        // PIBeta = ZKP{pi * x4}
        const PIBeta = await this.createZKP(
            secret,
            beta_G,
            beta,
            this.serverId,
        );
        // package values
        const response = new AuthInitResponse(X3, X4, PI3, PI4, beta, PIBeta);
        // prettier-ignore
        const initial = new AuthInitialValues(T, pi, x4, X1, X2, X3, X4, beta,
            PI1, PI2, PI3, PIBeta);
        return { response, initial };
    }
    async authFinish(
        username: string,
        request: AuthFinishRequest,
        initial: AuthInitialValues,
    ): Promise<
        | {
              key: ArrayBuffer;
              kc: string;
              kcTest: string;
          }
        | AuthenticationFailure
        | ZKPVerificationFailure
    > {
        const { T, pi, x4, X1, X2, X3, X4, beta, PI1, PI2, PI3, PIBeta } =
            initial;
        const { alpha, PIAlpha, r } = request;
        // verify alpha ZKP
        const alpha_G = X1.add(X3).add(X4);
        if (!(await this.verifyZKP(PIAlpha, alpha_G, alpha, username))) {
            return new ZKPVerificationFailure();
        }
        // K = (alpha - (X2 * (x4 * pi))) * x4
        const K = alpha.subtract(X2.multiply(this.modN(x4 * pi))).multiply(x4);
        // h = H(K||Transcript)
        // prettier-ignore
        const h = await this.H(K, username, X1, X2, PI1.h, PI1.r, PI2.h, PI2.r,
            this.serverId, X3, X4, PI3.h, PI3.r, beta, PIBeta.h, PIBeta.r,
            alpha, PIAlpha.h, PIAlpha.r);
        // (G * r) + (T * h) ?= X1
        if (!this.G.multiply(r).add(T.multiply(h)).equals(X1)) {
            return new AuthenticationFailure();
        }
        // k = H(K)
        const k = await crypto.subtle.digest("SHA-256", K.toRawBytes());
        // kc = HMAC(K || "KC" || serverId || userId || X3 || X4 || X1 || X2)
        const kc = await this.HMAC(K, this.serverId, username, X3, X4, X1, X2);
        // check received key confirmation matches expected result
        // prettier-ignore
        const kcTest = await this.HMAC(K, username, this.serverId, X1, X2, X3, X4);
        return { key: k, kc, kcTest };
    }
}
