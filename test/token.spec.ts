import { describe, it, expect, beforeAll } from 'bun:test'
import { signToken, verifyToken, decodeToken } from '../src/token'

let keyPair: CryptoKeyPair
let wrongKeyPair: CryptoKeyPair

beforeAll(async () => {
  // Generate RSA key pairs for testing
  keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  )

  wrongKeyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  )
})

describe('🗲 signToken / verifyToken', () => {
  it('signs and verifies a simple token', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, { sub: 'abc', iat: now, exp: now + 60 }, { kid: 'key-1' })
    const payload = await verifyToken(token, keyPair.publicKey)
    expect(payload?.sub).toBe('abc')
  })

  it('fails verification with wrong public key', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, { sub: 'abc', iat: now, exp: now + 60 }, { kid: 'key-1' })
    const payload = await verifyToken(token, wrongKeyPair.publicKey)
    expect(payload).toBeNull()
  })

  it('respects exp claim (expired)', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, { sub: 'abc', iat: now - 120, exp: now - 60 }, { kid: 'key-1' })
    const payload = await verifyToken(token, keyPair.publicKey)
    expect(payload).toBeNull()
  })

  it('respects nbf claim (not yet valid)', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, { sub: 'abc', iat: now, nbf: now + 60, exp: now + 120 }, { kid: 'key-1' })
    const payload = await verifyToken(token, keyPair.publicKey)
    expect(payload).toBeNull()
  })

  it('supports customValidate hook', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, { sub: 'admin', iat: now, exp: now + 60 }, { kid: 'key-1' })
    const payload = await verifyToken(token, keyPair.publicKey, (p) => p.sub === 'admin')
    expect(payload?.sub).toBe('admin')
  })

  it('fails customValidate hook if returns false', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, { sub: 'user', iat: now, exp: now + 60 }, { kid: 'key-1' })
    const payload = await verifyToken(token, keyPair.publicKey, (p) => p.sub === 'admin')
    expect(payload).toBeNull()
  })

  it('respects standard claims (iss, aud, sub)', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, {
      iss: 'me', aud: 'you', sub: 'abc', iat: now, exp: now + 60
    }, { kid: 'key-1' })
    const payload = await verifyToken(token, keyPair.publicKey, (p) => {
      return p.iss === 'me' && p.aud === 'you' && p.sub === 'abc'
    })
    expect(payload?.iss).toBe('me')
  })

  it('generates token with proper structure', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, { sub: 'abc', iat: now, exp: now + 60 }, { kid: 'key-1' })
    const parts = token.split('.')
    expect(parts.length).toBe(3)
  })
})

describe('🗲 decodeToken', () => {
  it('decodes a token without verifying', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(keyPair.privateKey, { sub: 'abc', iat: now, exp: now + 60 })
    const { header, payload, signature } = decodeToken(token)
    expect(header?.alg).toBe('RS256')
    expect(payload?.sub).toBe('abc')
    expect(typeof signature).toBe('string')
  })

  it('returns null fields if token is invalid', () => {
    const { header, payload, signature } = decodeToken('invalid.token')
    expect(header).toBeNull()
    expect(payload).toBeNull()
    expect(signature).toBeNull()
  })
})
