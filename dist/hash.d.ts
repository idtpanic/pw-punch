import { HashType } from './types';
/**
 * 🗲 Hashes a password using PBKDF2 with SHA-256 or SHA-512 and a random 32-byte salt.
 *
 * @param password - The plain-text password to hash.
 * @param type - Hash algorithm to use: 256 (SHA-256) or 512 (SHA-512). Default is 256.
 * @param iterations - Number of PBKDF2 iterations to apply. Default is 150,000. Min: 100,000, Max: 500,000.
 * @returns A string in the format "salt:hash", both base64-encoded.
 * @throws If the hash type is unsupported or iteration count is out of bounds.
 */
export declare function hashPassword(password: string, type?: HashType, iterations?: number): Promise<string>;
/**
 * 🗲 Verifies a password against a PBKDF2 hash (format: "salt:hash", both base64-encoded).
 *
 * @param password - The plain-text password to verify.
 * @param hashed - The stored hash string in the format "salt:hash" (base64).
 * @param type - Hash algorithm to use: 256 (SHA-256) or 512 (SHA-512). Default is 256.
 * @param iterations - Number of PBKDF2 iterations used during hashing. Must match the original. Default is 150,000. Min: 100,000, Max: 500,000.
 * @returns `true` if the password matches the hash, otherwise `false`.
 */
export declare function verifyPassword(password: string, hashed: string, type?: HashType, iterations?: number): Promise<boolean>;
