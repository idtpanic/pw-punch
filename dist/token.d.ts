import { HashType, TokenPayload, JwtHeader } from './types';
/**
 * 🗲 Signs a payload into a JWT using HMAC and SHA-256/512.
 *
 * @param payload - The JWT payload object (sub, iat, exp, etc.).
 * @param secret - Secret key used for HMAC signature.
 * @param type - Hash algorithm to use: 256 (SHA-256) or 512 (SHA-512). Default is 256.
 * @param kid - Optional key ID (kid) for key rotation support.
 * @returns A signed JWT as a string in the format `header.payload.signature`.
 * @throws If the payload or hash type is invalid, or encoding fails.
 */
export declare function signToken(payload: TokenPayload, secret: string, type?: HashType, kid?: string): Promise<string>;
/**
 * 🗲 Verifies a JWT using HMAC and SHA-256/512.
 *
 * @param token - The JWT string to verify (format: `header.payload.signature`).
 * @param secrets - Secret key or map of keys (with `kid`) used for verification.
 * @param type - Hash algorithm used: 256 (SHA-256) or 512 (SHA-512). Default is 256.
 * @param customValidate - Optional custom validation function for additional claim checks.
 * @returns The decoded and validated payload object, or `null` if verification fails.
 */
export declare function verifyToken(token: string, secrets: string | Record<string, string>, type?: HashType, customValidate?: (payload: TokenPayload) => boolean): Promise<TokenPayload | null>;
/**
 * 🧠 Decodes a JWT into its parts without verifying.
 *
 * @param token - The JWT string to decode (format: `header.payload.signature`).
 * @returns An object containing decoded `header`, `payload`, and `signature` (or `null` if malformed).
 */
export declare function decodeToken(token: string): {
    header: JwtHeader | null;
    payload: TokenPayload | null;
    signature: string | null;
};
