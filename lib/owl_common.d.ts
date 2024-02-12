import BigNumber from "bignumber.js";
interface Config {
    p: string;
    q: string;
    g: string;
    serverId: string;
}
interface ParsedConfig {
    p: BigNumber;
    q: BigNumber;
    g: BigNumber;
    serverId: string;
}
export interface ZKP {
    h: BigNumber;
    r: BigNumber;
}
export declare class ZKPVerificationFailure extends Error {
    constructor();
}
export declare class OwlCommon {
    config: ParsedConfig;
    constructor(config: Config);
    /**
     * Generate a cryptographically secure random number
     * between from and to inclusive
     * @param from Lower limit
     * @param to Upper limit
     * @returns Random number
     */
    rand(from: BigNumber, to: BigNumber): BigNumber;
    /**
     * Concatenate the given numbers and strings into one string
     * @param args Any number of BigNumber or string objects
     * @returns Concatenated objects
     */
    concat(...args: Array<BigNumber | string>): string;
    /**
     * Hash a string and convert it to a BigNumber
     * @param x Input string
     * @returns BigNumber from hash output
     */
    H(x: string): Promise<BigNumber>;
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
    createZKP(x: BigNumber, g: BigNumber, X: BigNumber, prover: string): Promise<ZKP>;
    /**
     * Modular exponentiation with support for negative exponents
     * @param x Base
     * @param e Exponent
     * @param m Modulus
     * @returns x^e % m
     */
    modExp(x: BigNumber, e: BigNumber, m: BigNumber): BigNumber | Error;
    /**
     * Verify the given ZKP for the given generator, public key
     * and prover identity
     * @param zkp ZKP to verify
     * @param g Generator
     * @param X Public key
     * @param prover Prover identity
     */
    verifyZKP(zkp: ZKP, g: BigNumber, X: BigNumber, prover: string): Promise<boolean>;
}
export {};
//# sourceMappingURL=owl_common.d.ts.map