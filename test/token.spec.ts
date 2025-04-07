import { describe, it, expect } from 'bun:test'
import { signToken, verifyToken, decodeToken } from '../src/token'

const secret = 'test-secret-key'
const badSecret = 'wrong-secret-key'

describe('🗲 signToken / verifyToken', () => {
  it('signs and verifies a simple token', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'abc', iat: now, exp: now + 60 }, secret)
    const payload = await verifyToken(token, secret)
    expect(payload?.sub).toBe('abc')
  })

  it('fails verification with wrong secret', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'abc', iat: now, exp: now + 60 }, secret)
    const payload = await verifyToken(token, badSecret)
    expect(payload).toBeNull()
  })

  it('respects exp claim (expired)', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'abc', iat: now - 120, exp: now - 60 }, secret)
    const payload = await verifyToken(token, secret)
    expect(payload).toBeNull()
  })

  it('respects nbf claim (not yet valid)', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'abc', iat: now, nbf: now + 60, exp: now + 120 }, secret)
    const payload = await verifyToken(token, secret)
    expect(payload).toBeNull()
  })

  it('supports key rotation with kid', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'abc', iat: now, exp: now + 60 }, secret, 256, 'v1')
    const result = await verifyToken(token, { v1: secret })
    expect(result?.sub).toBe('abc')
  })

  it('fails if kid does not match secrets map', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'abc', iat: now, exp: now + 60 }, secret, 256, 'v1')
    const result = await verifyToken(token, { wrong: secret })
    expect(result).toBeNull()
  })

  it('supports customValidate hook', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'admin', iat: now, exp: now + 60 }, secret)
    const payload = await verifyToken(token, secret, 256, (p) => p.sub === 'admin')
    expect(payload?.sub).toBe('admin')
  })

  it('fails customValidate hook if returns false', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'user', iat: now, exp: now + 60 }, secret)
    const payload = await verifyToken(token, secret, 256, (p) => p.sub === 'admin')
    expect(payload).toBeNull()
  })

  it('respects standard claims (iss, aud, sub)', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken(
      { iss: 'me', aud: 'you', sub: 'abc', iat: now, exp: now + 60 },
      secret
    )
    const payload = await verifyToken(token, secret, 256, (p) => {
      return p.iss === 'me' && p.aud === 'you' && p.sub === 'abc'
    })
    expect(payload?.iss).toBe('me')
  })

  it('generates shorter token if manually passed (no typ/kid)', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'abc', iat: now, exp: now + 60 }, secret)
    const parts = token.split('.')
    expect(parts.length).toBe(3)
    expect(token.length).toBeLessThan(300)
  })
})

describe('🗲 decodeToken', () => {
  it('decodes a token without verifying', async () => {
    const now = Math.floor(Date.now() / 1000)
    const token = await signToken({ sub: 'abc', iat: now, exp: now + 60 }, secret)
    const { header, payload, signature } = decodeToken(token)
    expect(header?.alg).toMatch(/^HS(256|512)$/)
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
