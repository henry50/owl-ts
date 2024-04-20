// THIS FILE IS GENERATED BY _messagesGenerator.ts
// DO NOT EDIT IT DIRECTLY AS IT WILL BE OVERWRITTEN

import { Config, Curves, Point, ZKP } from "./owl_common.js";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";

function getCurve(curve: Curves) {
    return {
        [Curves.P256]: p256,
        [Curves.P384]: p384,
        [Curves.P521]: p521,
    }[curve];
}

function parseNum(x: any): bigint | null {
    try {
        return BigInt(`0x${x}`);
    } catch {
        return null;
    }
}

function parsePoint(x: any, curve: Curves): Point | null {
    try {
        return getCurve(curve).ProjectivePoint.fromHex(x);
    } catch {
        return null;
    }
}

function parseZKP(x: any): ZKP | null {
    try {
        const [h, r] = [parseNum(x.h), parseNum(x.r)];
        if (h && r) {
            return { h, r };
        }
    } catch {}
    return null;
}

export class DeserializationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "DeserializationError";
    }
}

export class RegistrationRequest {
    pi: bigint;
    T: Point;
    constructor(pi: bigint, T: Point) {
        [this.pi, this.T] = [pi, T];
    }
    static deserialize(
        x: any,
        cfg: Config,
    ): RegistrationRequest | DeserializationError {
        if (typeof x == "string") {
            x = JSON.parse(x);
        }
        if (!!x) {
            const [pi, T] = [parseNum(x.pi), parsePoint(x.T, cfg.curve)];
            if (pi !== null && T !== null) {
                return new this(pi, T);
            }
        }
        return new DeserializationError(
            "Failed to deserialize RegistrationRequest: invalid data",
        );
    }
    serialize() {
        return {
            pi: this.pi.toString(16),
            T: this.T.toHex(),
        };
    }
}

export class UserCredentials {
    X3: Point;
    PI3: ZKP;
    pi: bigint;
    T: Point;
    constructor(X3: Point, PI3: ZKP, pi: bigint, T: Point) {
        [this.X3, this.PI3, this.pi, this.T] = [X3, PI3, pi, T];
    }
    static deserialize(
        x: any,
        cfg: Config,
    ): UserCredentials | DeserializationError {
        if (typeof x == "string") {
            x = JSON.parse(x);
        }
        if (!!x) {
            const [X3, PI3, pi, T] = [
                parsePoint(x.X3, cfg.curve),
                parseZKP(x.PI3),
                parseNum(x.pi),
                parsePoint(x.T, cfg.curve),
            ];
            if (X3 !== null && PI3 !== null && pi !== null && T !== null) {
                return new this(X3, PI3, pi, T);
            }
        }
        return new DeserializationError(
            "Failed to deserialize UserCredentials: invalid data",
        );
    }
    serialize() {
        return {
            X3: this.X3.toHex(),
            PI3: { h: this.PI3.h.toString(16), r: this.PI3.r.toString(16) },
            pi: this.pi.toString(16),
            T: this.T.toHex(),
        };
    }
}

export class AuthInitRequest {
    X1: Point;
    X2: Point;
    PI1: ZKP;
    PI2: ZKP;
    constructor(X1: Point, X2: Point, PI1: ZKP, PI2: ZKP) {
        [this.X1, this.X2, this.PI1, this.PI2] = [X1, X2, PI1, PI2];
    }
    static deserialize(
        x: any,
        cfg: Config,
    ): AuthInitRequest | DeserializationError {
        if (typeof x == "string") {
            x = JSON.parse(x);
        }
        if (!!x) {
            const [X1, X2, PI1, PI2] = [
                parsePoint(x.X1, cfg.curve),
                parsePoint(x.X2, cfg.curve),
                parseZKP(x.PI1),
                parseZKP(x.PI2),
            ];
            if (X1 !== null && X2 !== null && PI1 !== null && PI2 !== null) {
                return new this(X1, X2, PI1, PI2);
            }
        }
        return new DeserializationError(
            "Failed to deserialize AuthInitRequest: invalid data",
        );
    }
    serialize() {
        return {
            X1: this.X1.toHex(),
            X2: this.X2.toHex(),
            PI1: { h: this.PI1.h.toString(16), r: this.PI1.r.toString(16) },
            PI2: { h: this.PI2.h.toString(16), r: this.PI2.r.toString(16) },
        };
    }
}

export class AuthInitialValues {
    T: Point;
    pi: bigint;
    x4: bigint;
    X1: Point;
    X2: Point;
    X3: Point;
    X4: Point;
    beta: Point;
    PI1: ZKP;
    PI2: ZKP;
    PI3: ZKP;
    PIBeta: ZKP;
    constructor(
        T: Point,
        pi: bigint,
        x4: bigint,
        X1: Point,
        X2: Point,
        X3: Point,
        X4: Point,
        beta: Point,
        PI1: ZKP,
        PI2: ZKP,
        PI3: ZKP,
        PIBeta: ZKP,
    ) {
        [
            this.T,
            this.pi,
            this.x4,
            this.X1,
            this.X2,
            this.X3,
            this.X4,
            this.beta,
            this.PI1,
            this.PI2,
            this.PI3,
            this.PIBeta,
        ] = [T, pi, x4, X1, X2, X3, X4, beta, PI1, PI2, PI3, PIBeta];
    }
    static deserialize(
        x: any,
        cfg: Config,
    ): AuthInitialValues | DeserializationError {
        if (typeof x == "string") {
            x = JSON.parse(x);
        }
        if (!!x) {
            const [T, pi, x4, X1, X2, X3, X4, beta, PI1, PI2, PI3, PIBeta] = [
                parsePoint(x.T, cfg.curve),
                parseNum(x.pi),
                parseNum(x.x4),
                parsePoint(x.X1, cfg.curve),
                parsePoint(x.X2, cfg.curve),
                parsePoint(x.X3, cfg.curve),
                parsePoint(x.X4, cfg.curve),
                parsePoint(x.beta, cfg.curve),
                parseZKP(x.PI1),
                parseZKP(x.PI2),
                parseZKP(x.PI3),
                parseZKP(x.PIBeta),
            ];
            if (
                T !== null &&
                pi !== null &&
                x4 !== null &&
                X1 !== null &&
                X2 !== null &&
                X3 !== null &&
                X4 !== null &&
                beta !== null &&
                PI1 !== null &&
                PI2 !== null &&
                PI3 !== null &&
                PIBeta !== null
            ) {
                return new this(
                    T,
                    pi,
                    x4,
                    X1,
                    X2,
                    X3,
                    X4,
                    beta,
                    PI1,
                    PI2,
                    PI3,
                    PIBeta,
                );
            }
        }
        return new DeserializationError(
            "Failed to deserialize AuthInitialValues: invalid data",
        );
    }
    serialize() {
        return {
            T: this.T.toHex(),
            pi: this.pi.toString(16),
            x4: this.x4.toString(16),
            X1: this.X1.toHex(),
            X2: this.X2.toHex(),
            X3: this.X3.toHex(),
            X4: this.X4.toHex(),
            beta: this.beta.toHex(),
            PI1: { h: this.PI1.h.toString(16), r: this.PI1.r.toString(16) },
            PI2: { h: this.PI2.h.toString(16), r: this.PI2.r.toString(16) },
            PI3: { h: this.PI3.h.toString(16), r: this.PI3.r.toString(16) },
            PIBeta: {
                h: this.PIBeta.h.toString(16),
                r: this.PIBeta.r.toString(16),
            },
        };
    }
}

export class AuthInitResponse {
    X3: Point;
    X4: Point;
    PI3: ZKP;
    PI4: ZKP;
    beta: Point;
    PIBeta: ZKP;
    constructor(
        X3: Point,
        X4: Point,
        PI3: ZKP,
        PI4: ZKP,
        beta: Point,
        PIBeta: ZKP,
    ) {
        [this.X3, this.X4, this.PI3, this.PI4, this.beta, this.PIBeta] = [
            X3,
            X4,
            PI3,
            PI4,
            beta,
            PIBeta,
        ];
    }
    static deserialize(
        x: any,
        cfg: Config,
    ): AuthInitResponse | DeserializationError {
        if (typeof x == "string") {
            x = JSON.parse(x);
        }
        if (!!x) {
            const [X3, X4, PI3, PI4, beta, PIBeta] = [
                parsePoint(x.X3, cfg.curve),
                parsePoint(x.X4, cfg.curve),
                parseZKP(x.PI3),
                parseZKP(x.PI4),
                parsePoint(x.beta, cfg.curve),
                parseZKP(x.PIBeta),
            ];
            if (
                X3 !== null &&
                X4 !== null &&
                PI3 !== null &&
                PI4 !== null &&
                beta !== null &&
                PIBeta !== null
            ) {
                return new this(X3, X4, PI3, PI4, beta, PIBeta);
            }
        }
        return new DeserializationError(
            "Failed to deserialize AuthInitResponse: invalid data",
        );
    }
    serialize() {
        return {
            X3: this.X3.toHex(),
            X4: this.X4.toHex(),
            PI3: { h: this.PI3.h.toString(16), r: this.PI3.r.toString(16) },
            PI4: { h: this.PI4.h.toString(16), r: this.PI4.r.toString(16) },
            beta: this.beta.toHex(),
            PIBeta: {
                h: this.PIBeta.h.toString(16),
                r: this.PIBeta.r.toString(16),
            },
        };
    }
}

export class AuthFinishRequest {
    alpha: Point;
    PIAlpha: ZKP;
    r: bigint;
    constructor(alpha: Point, PIAlpha: ZKP, r: bigint) {
        [this.alpha, this.PIAlpha, this.r] = [alpha, PIAlpha, r];
    }
    static deserialize(
        x: any,
        cfg: Config,
    ): AuthFinishRequest | DeserializationError {
        if (typeof x == "string") {
            x = JSON.parse(x);
        }
        if (!!x) {
            const [alpha, PIAlpha, r] = [
                parsePoint(x.alpha, cfg.curve),
                parseZKP(x.PIAlpha),
                parseNum(x.r),
            ];
            if (alpha !== null && PIAlpha !== null && r !== null) {
                return new this(alpha, PIAlpha, r);
            }
        }
        return new DeserializationError(
            "Failed to deserialize AuthFinishRequest: invalid data",
        );
    }
    serialize() {
        return {
            alpha: this.alpha.toHex(),
            PIAlpha: {
                h: this.PIAlpha.h.toString(16),
                r: this.PIAlpha.r.toString(16),
            },
            r: this.r.toString(16),
        };
    }
}
