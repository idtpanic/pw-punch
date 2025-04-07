import { describe, it, expect } from 'bun:test'
import { hashPassword, verifyPassword } from '../dist'
import { MIN_ITER, MAX_ITER } from '../src/utils'

describe('🗲 hashPassword', () => {
  it('should generate a valid hash string', async () => {
    const result = await hashPassword('hunter2')
    expect(typeof result).toBe('string')
    expect(result.split(':')).toHaveLength(2)
  })

  it('should throw for unsupported hash type', async () => {
    await expect(hashPassword('pw', 999 as any)).rejects.toThrow()
  })

  it('should throw if iterations too low', async () => {
    await expect(hashPassword('pw', 256, MIN_ITER - 1)).rejects.toThrow()
  })

  it('should throw if iterations too high', async () => {
    await expect(hashPassword('pw', 256, MAX_ITER + 1)).rejects.toThrow()
  })
})

describe('🗲 verifyPassword', () => {
  it('should verify a valid password', async () => {
    const password = 'hunter2'
    const hash = await hashPassword(password)
    const result = await verifyPassword(password, hash)
    expect(result).toBe(true)
  })

  it('should return false for wrong password', async () => {
    const hash = await hashPassword('correct_password')
    const result = await verifyPassword('wrong_password', hash)
    expect(result).toBe(false)
  })

  it('should return false for malformed hash', async () => {
    const result = await verifyPassword('password', 'not:base64')
    expect(result).toBe(false)
  })
})
