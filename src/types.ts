export type HashType = 256 | 512
export type TokenType = 'RS256'
export type HashTypeString = 'SHA-256' | 'SHA-512'

export interface TokenPayload {
  iss?: string
  sub?: string
  aud?: string
  exp?: number
  nbf?: number
  iat?: number
  [key: string]: any
}

export interface SafePayloadOptions {
  iss?: string
  sub?: string
  aud?: string
  iat?: number
  nbf?: number
  exp?: number
  expSeconds?: number
}

export interface ValidateOptions {
  iss?: string
  sub?: string
  aud?: string
}

export interface JwtHeader {
  alg: TokenType
  typ?: 'JWT'
  kid?: string
  [key: string]: any
}
