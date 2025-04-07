import {
  MAX_ITER,
  MIN_ITER,
  DEFAULT_ITERATIONS,
  DEFAULT_HASH_TYPE,
  SUPPORTED_HASH_TYPES,
  timingSafeEqualUint8Array,
  base64ToUint8Array,
  punchImportKey,
  punchDeriveBits,
} from './utils'

import { HashType } from './types'

/**
 * 🗲 Hashes a password using PBKDF2 with SHA-256 or SHA-512 and a random 32-byte salt.
 *
 * @param password - The plain-text password to hash.
 * @param type - Hash algorithm to use: 256 (SHA-256) or 512 (SHA-512). Default is 256.
 * @param iterations - Number of PBKDF2 iterations to apply. Default is 150,000. Min: 100,000, Max: 500,000.
 * @returns A string in the format "salt:hash", both base64-encoded.
 * @throws If the hash type is unsupported or iteration count is out of bounds.
 */

export async function hashPassword(
  password: string,
  type: HashType = DEFAULT_HASH_TYPE,
  iterations: number = DEFAULT_ITERATIONS
): Promise<string> {
  if (iterations < MIN_ITER || iterations > MAX_ITER)
    throw new Error(`Iterations must be between ${MIN_ITER} and ${MAX_ITER}`)
  if (!SUPPORTED_HASH_TYPES.includes(type))
    throw new Error('Only SHA-256 and SHA-512 are supported')
  const salt = crypto.getRandomValues(new Uint8Array(32))

  const key = await punchImportKey(password)
  const hash = await punchDeriveBits(key, salt.buffer, iterations, `SHA-${type}`)

  const saltBase64 = btoa(String.fromCharCode(...salt))
  const hashBase64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
  return `${saltBase64}:${hashBase64}`
}

/**
 * 🗲 Verifies a password against a PBKDF2 hash (format: "salt:hash", both base64-encoded).
 *
 * @param password - The plain-text password to verify.
 * @param hashed - The stored hash string in the format "salt:hash" (base64).
 * @param type - Hash algorithm to use: 256 (SHA-256) or 512 (SHA-512). Default is 256.
 * @param iterations - Number of PBKDF2 iterations used during hashing. Must match the original. Default is 150,000. Min: 100,000, Max: 500,000.
 * @returns `true` if the password matches the hash, otherwise `false`.
 */

export async function verifyPassword(
  password: string,
  hashed: string,
  type: HashType = DEFAULT_HASH_TYPE,
  iterations: number = DEFAULT_ITERATIONS
): Promise<boolean> {
  const [saltBase64, hashBase64] = hashed.split(':')
  if (!saltBase64 || !hashBase64) return false

  const salt = base64ToUint8Array(saltBase64)
  const storedHash = base64ToUint8Array(hashBase64)
  const key = await punchImportKey(password)
  const hash = await punchDeriveBits(key, salt.buffer, iterations, `SHA-${type}`)

  return timingSafeEqualUint8Array(new Uint8Array(hash), storedHash)
}
