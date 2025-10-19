import { HashType, HashTypeString, TokenType, TokenPayload, ValidateOptions, SafePayloadOptions } from './types'

export const MIN_EXP: number = 60 // 1min
export const MAX_EXP: number = 2_592_000  // 30days
export const MIN_ITER: number = 100_000
export const MAX_ITER: number = 500_000
export const DEFAULT_EXP: number = 3600
export const MAX_BYTE_LENGTH: number = 10_000
export const ENCODER: TextEncoder = new TextEncoder()
export const SUPPORTED_HASH_TYPES: HashType[] = [256, 512]
export const DEFAULT_ITERATIONS: number = 150_000
export const DEFAULT_HASH_TYPE: HashType = 256
export const DEFAULT_TOKEN_TYPE:TokenType = 'RS256'

export async function punchImportKey(password: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    ENCODER.encode(password),
    {
      name: 'PBKDF2',
    },
    false,
    ['deriveBits']
  )
}

export async function punchDeriveBits(
  key: CryptoKey,
  buffer: BufferSource,
  iterations: number,
  type: HashTypeString
): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: buffer,
      iterations: iterations,
      hash: type,
    },
    key,
    256
  )
}



// 🛡️ Validate token payload
export function validateToken(payload: TokenPayload, options?: ValidateOptions): boolean {
  const now = Math.floor(Date.now() / 1000)
  if (payload.exp !== undefined && now >= payload.exp) return false
  if (payload.nbf !== undefined && now < payload.nbf) return false
  // iat should not be more than 5 seconds in the future (clock skew tolerance)
  if (payload.iat !== undefined && now < payload.iat - 5) return false

  if (options?.iss && payload.iss !== options.iss) return false
  if (options?.sub && payload.sub !== options.sub) return false
  if (options?.aud && payload.aud !== options.aud) return false
  return true
}

// 🛡️ Timing-safe comparison for Uint8Array
export function timingSafeEqualUint8Array(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array))
    throw new TypeError('Inputs must be Uint8Arrays')
  if (Math.max(a.length, b.length) > MAX_BYTE_LENGTH) throw new Error('Input too large')

  let diff = 0
  const max = Math.max(a.length, b.length)
  for (let i = 0; i < max; i++) {
    const av = i < a.length ? a[i] : 0
    const bv = i < b.length ? b[i] : 0
    diff |= av ^ bv
  }
  return diff === 0
}


// 🛡️ Convert a base64url-encoded string to Uint8Array for cryptographic use
export function base64ToUint8Array(base64: string): Uint8Array {
  base64 = base64.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4 !== 0) base64 += '='
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0))
}

// 🛡️ Convert Uint8Array to base64url
export function base64urlEncode(input: string | Uint8Array): string {
  const str = typeof input === 'string' ? input : String.fromCharCode(...input)
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// 🛡️ Decode base64url to string
function base64urlDecode(input: string): string {
  input = input.replace(/-/g, '+').replace(/_/g, '/')
  while (input.length % 4 !== 0) input += '='
  return atob(input)
}

// 🛡️ Generate a safe payload with default claims
export function safePayload(
  payload: TokenPayload,
  options: SafePayloadOptions = {}
): TokenPayload {
  const now = Math.floor(Date.now() / 1000)
  const iat = payload.iat ?? options.iat ?? now
  const nbf = payload.nbf ?? options.nbf ?? iat
  const expSeconds = options.expSeconds ?? DEFAULT_EXP
  const exp = payload.exp ?? options.exp ?? (iat + expSeconds)

  return { ...payload, iat, nbf, exp }
}

// 🛡️ Parse JWT part (header or payload)
export function parsePart<T = any>(input: string): T | null {
  try {
    return JSON.parse(base64urlDecode(input))
  } catch {
    return null
  }
}
