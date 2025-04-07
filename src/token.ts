import {
  ENCODER,
  DEFAULT_HASH_TYPE,
  SUPPORTED_HASH_TYPES,
  base64ToUint8Array,
  punchTokenKey,
  validateToken,
  parsePart,
  base64urlEncode,
  safePayload
} from './utils'
import { HashType, TokenPayload, JwtHeader } from './types'

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

export async function signToken(
  payload: TokenPayload,
  secret: string,
  type: HashType = DEFAULT_HASH_TYPE,
  kid?: string,
): Promise<string> {
  if (
    !SUPPORTED_HASH_TYPES.includes(type) ||
    typeof payload !== 'object' ||
    payload === null ||
    Array.isArray(payload)
  ) {
    throw new TypeError('Invalid token payload or unsupported hash type')
  }
  
  const newPayload = safePayload(payload)
  const header: JwtHeader = { alg: `HS${type}`, typ: 'JWT', ...(kid ? { kid } : {}), ...(payload.iss ? { iss: payload.iss } : {}) }
  let encodedHeader: string, encodedPayload: string
  try {
    encodedHeader = base64urlEncode(JSON.stringify(header))
    encodedPayload = base64urlEncode(JSON.stringify(newPayload))
  } catch {
    throw new Error('Failed to encode token payload or header')
  }
  const data = `${encodedHeader}.${encodedPayload}`
  const key = await punchTokenKey(secret, `SHA-${type}`, 'sign')

  const signature = await crypto.subtle.sign('HMAC', key, ENCODER.encode(data))
  const encodedSignature = base64urlEncode(new Uint8Array(signature))

  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`
}

/**
 * 🗲 Verifies a JWT using HMAC and SHA-256/512.
 *
 * @param token - The JWT string to verify (format: `header.payload.signature`).
 * @param secrets - Secret key or map of keys (with `kid`) used for verification.
 * @param type - Hash algorithm used: 256 (SHA-256) or 512 (SHA-512). Default is 256.
 * @param customValidate - Optional custom validation function for additional claim checks.
 * @returns The decoded and validated payload object, or `null` if verification fails.
 */

export async function verifyToken(
  token: string,
  secrets: string | Record<string, string>,
  type: HashType = DEFAULT_HASH_TYPE,
  customValidate?: (payload: TokenPayload) => boolean
): Promise<TokenPayload | null> {
  const [headerB64, payloadB64, signatureB64] = token.split('.')
  if (!headerB64 || !payloadB64 || !signatureB64 || signatureB64.length > 1024) return null

  let actualSecret: string | null = null

  const header: JwtHeader | null = parsePart(headerB64)
  if (!header || header.alg !== `HS${type}`) return null
  
  if (typeof secrets === 'string') {
    actualSecret = secrets
  } else if (typeof secrets === 'object') {
    const kid = header.kid
    if (!kid || !secrets[kid]) return null
    actualSecret = secrets[kid]
  }
  if (!actualSecret) return null
  
  const data = `${headerB64}.${payloadB64}`
  const key = await punchTokenKey(actualSecret, `SHA-${type}`, 'verify')

  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    base64ToUint8Array(signatureB64),
    ENCODER.encode(data)
  )
  if (!valid) return null

  const payload = parsePart<TokenPayload>(payloadB64)
  if (!payload || !validateToken(payload)) return null

  if (customValidate && !customValidate(payload)) return null

  return payload
}

/**
 * 🧠 Decodes a JWT into its parts without verifying.
 *
 * @param token - The JWT string to decode (format: `header.payload.signature`).
 * @returns An object containing decoded `header`, `payload`, and `signature` (or `null` if malformed).
 */

export function decodeToken(token: string): {
  header: JwtHeader | null
  payload: TokenPayload | null
  signature: string | null
} {
  const [headerB64, payloadB64, signatureB64] = token.split('.')
  return {
    header: headerB64 ? parsePart(headerB64) : null,
    payload: payloadB64 ? parsePart(payloadB64) : null,
    signature: signatureB64 ?? null,
  }
}
