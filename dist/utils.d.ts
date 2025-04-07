import { HashType, HashTypeString, TokenPayload, UseType, ValidateOptions, SafePayloadOptions } from './types';
export declare const MIN_EXP: number;
export declare const MAX_EXP: number;
export declare const MIN_ITER: number;
export declare const MAX_ITER: number;
export declare const DEFAULT_EXP: number;
export declare const MAX_BYTE_LENGTH: number;
export declare const ENCODER: TextEncoder;
export declare const SUPPORTED_HASH_TYPES: HashType[];
export declare const DEFAULT_ITERATIONS = 150000;
export declare const DEFAULT_HASH_TYPE = 256;
export declare function punchImportKey(password: string): Promise<CryptoKey>;
export declare function punchDeriveBits(key: CryptoKey, buffer: BufferSource, iterations: number, type: HashTypeString): Promise<ArrayBuffer>;
export declare function punchTokenKey(secret: string, type: HashTypeString, use: UseType): Promise<CryptoKey>;
export declare function validateToken(payload: TokenPayload, options?: ValidateOptions): boolean;
export declare function timingSafeEqualUint8Array(a: Uint8Array, b: Uint8Array): boolean;
export declare function base64ToUint8Array(base64: string): Uint8Array;
export declare function base64urlEncode(input: string | Uint8Array): string;
export declare function safePayload(payload: TokenPayload, options?: SafePayloadOptions): TokenPayload;
export declare function parsePart<T = any>(input: string): T | null;
