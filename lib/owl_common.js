import BigNumber from "bignumber.js";
export class ZKPVerificationFailure extends Error {
    constructor() {
        super("ZKP verification failed");
        this.name = "ZKPVerificationFailure";
    }
}
export class OwlCommon {
    config;
    constructor(config) {
        this.config = {
            p: BigNumber(config.p),
            q: BigNumber(config.q),
            g: BigNumber(config.g),
            serverId: config.serverId
        };
    }
    /**
     * Generate a cryptographically secure random number
     * between from and to inclusive
     * @param from Lower limit
     * @param to Upper limit
     * @returns Random number
     */
    rand(from, to) {
        // use cryptographically secure PRNG
        BigNumber.config({ CRYPTO: true });
        // rand = floor(random() * (max - min + 1) + min)
        // to.precision(true) gets the log_10 of to which is then used
        // to determine the number of decimal places to randomly generate
        return BigNumber.random(to.precision(true))
            .multipliedBy(to.minus(from).plus(1)).plus(from)
            .integerValue(BigNumber.ROUND_FLOOR);
    }
    /**
     * Concatenate the given numbers and strings into one string
     * @param args Any number of BigNumber or string objects
     * @returns Concatenated objects
     */
    concat(...args) {
        // 
        let ret = "";
        for (const arg of args) {
            if (arg instanceof BigNumber) {
                ret += arg.toString(16);
            }
            else {
                ret += arg;
            }
        }
        return ret;
    }
    /**
     * Hash a string and convert it to a BigNumber
     * @param x Input string
     * @returns BigNumber from hash output
     */
    async H(x) {
        // adapted from https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
        const msgUint8 = new TextEncoder().encode(x); // encode as Uint8Array
        const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8); // hash the message
        const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
        const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join(""); // convert bytes to hex string
        return BigNumber(hashHex, 16);
    }
    /**
     * Create a Schnorr Non-Interactive Zero Knowledge Proof (NIZKP)
     * from the given private key, generator, public key and
     * prover identity
     * @param x Private key
     * @param g Generator
     * @param X Public key
     * @param prover Prover identity
     * @returns Zero knowledge proof
     */
    async createZKP(x, g, X, prover) {
        const v = this.rand(BigNumber(0), this.config.q);
        const V = g.pow(v, this.config.p);
        const h = await this.H(this.concat(g, V, X, prover));
        const r = v.minus(x.times(h)).modulo(this.config.q);
        return { h, r };
    }
    /**
     * Modular exponentiation with support for negative exponents
     * @param x Base
     * @param e Exponent
     * @param m Modulus
     * @returns x^e % m
     */
    modExp(x, e, m) {
        if (e.lt(0)) {
            // use extended Euclidean algorithm to get inverse
            let [r1, r2] = [m, x];
            let [t1, t2] = [BigNumber(0), BigNumber(1)];
            while (!r2.eq(0)) {
                let quotient = r1.idiv(r2);
                [t1, t2] = [t2, t1.minus(quotient.times(t2))];
                [r1, r2] = [r2, r1.minus(quotient.times(r2))];
            }
            // if the protocol is followed correctly this will never occur as all numbers will be coprime
            if (r1.gt(1)) {
                return new Error("Could not find modular inverse, numbers are not coprime");
            }
            if (t1.lt(0)) {
                t1 = t1.plus(m);
            }
            // t1 is the inverse, t1^-e%m is equivalent to x^e%m
            return t1.pow(e.negated(), m);
        }
        else {
            return x.pow(e, m);
        }
    }
    /**
     * Verify the given ZKP for the given generator, public key
     * and prover identity
     * @param zkp ZKP to verify
     * @param g Generator
     * @param X Public key
     * @param prover Prover identity
     */
    async verifyZKP(zkp, g, X, prover) {
        const { h, r } = zkp;
        // check X has the correct prime order
        if (!(X.gte(1) &&
            X.lte(this.config.p.minus(1)) &&
            X.pow(this.config.q, this.config.p).eq(1))) {
            return false;
        }
        // (g^r * X^h) mod p = ((g^r mod p) * (X^h mod p)) mod p
        const gr = this.modExp(g, r, this.config.p);
        // check for non-coprime generator
        if (gr instanceof Error) {
            return false;
        }
        const grXh = gr.times(X.pow(h, this.config.p)).mod(this.config.p);
        const hTest = await this.H(this.concat(g, grXh, X, prover));
        return h.eq(hTest);
    }
}
