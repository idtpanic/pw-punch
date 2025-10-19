import { TokenPayload, JwtHeader } from './types';
/**
 * 🗲 Signs a JWT using RSASSA-PKCS1-v1_5 with SHA-256.
 *
 * @param privateKey - The RSA private key used for signing (CryptoKey).
 * @param payload - The payload object to include in the JWT.
 * @param options - Optional settings for token generation.
 * @param options.kid - Key ID for key rotation (optional).
 * @param options.includeTyp - Include "typ: JWT" in header. Default: true.
 * @returns A signed JWT string in the format `header.payload.signature`.
 * @throws Error if encoding fails or signing fails.
 */
export declare function signToken(privateKey: CryptoKey, payload: TokenPayload, options?: {
    kid?: string;
    includeTyp?: boolean;
}): Promise<string>;
/**
  * 🗲 Verifies a JWT signature and decodes its payload.
  * * @param token - The JWT string to verify (format: `header.payload.signature`).
  * @param publicKey - The public key used for verification (CryptoKey).
  * @param customValidate - Optional custom validation function for the payload.
  * @returns The decoded payload if valid, or `null` if verification fails.
  * @throws Error if the token format is invalid or signature verification fails.
  *
  * This function checks the JWT structure, verifies the signature using RSASSA-PKCS1-v1_5,
  * and validates the payload against standard claims (like `exp`, `nbf`, etc.) and any custom rules.
  * It returns the payload if all checks pass, or `null` if any check fails.
  * Note: The `publicKey` must be a valid CryptoKey object for verification to succeed.
  * If `customValidate` is provided, it will be called with the payload and must return `true` for the token to be considered valid.
  * This function is asynchronous and returns a Promise that resolves to the payload or `null`.
  *
 */
export declare function verifyToken(token: string, publicKey: CryptoKey | null, customValidate?: (payload: TokenPayload) => boolean): Promise<TokenPayload | null>;
/**
  * 🗲 Decodes a JWT into its header, payload, and signature parts.
  * @param token - The JWT string to decode (format: `header.payload.signature`).
  * @returns An object containing the decoded header, payload, and signature.
  * @throws Error if the token format is invalid or if parsing fails.
  * This function splits the JWT into its three components: header, payload, and signature.
  * It decodes each part from base64url format and parses the header and payload as JSON.
  * The signature is returned as a base64url string.
  * It does not validate the token; it simply decodes it.
  * The returned object will have the following structure:
  * {
  *   header: JwtHeader | null, // Parsed JWT header or null if missing
  *   payload: TokenPayload | null, // Parsed JWT payload or null if missing
  *   signature: string | null // Base64url encoded signature or null if missing
  * }
 */
export declare function decodeToken(token: string): {
    header: JwtHeader | null;
    payload: TokenPayload | null;
    signature: string | null;
};
