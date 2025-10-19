# 🥊 pw-punch

> 🔐 **Ultra-lightweight** password hashing & JWT-style token signing with pure **WebCrypto**.  
> Built for **Edge**, **Serverless**, and modern runtimes like **Cloudflare**, **Deno**, **Vercel**, **Bun** — _no Node.js required_.  
> **Zero dependencies. Zero overhead. Just crypto.**

---

## ⚡ Why pw-punch?

- ✅ **0 dependencies** — no extra weight
- ✅ **0 Node.js required** — pure WebCrypto API
- ✅ **0 config** — import and go
- ✅ **~4KB gzipped** — tiny footprint
- ✅ **Crypto only** — no extra fluff

---

## 🔐 Features

- 🔒 Password hashing with PBKDF2 + random salt
- ✍️ RSA-SHA256 (RS256) token signing (JWT standard)
- 🕵️ Token verification with standard claim checks (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`)
- 🔄 Supports key rotation (`kid` support)
- 🧪 Constant-time comparison utilities
- 🧩 WebCrypto only — works on:
  - ✅ Cloudflare Workers
  - ✅ Deno Deploy
  - ✅ Bun
  - ✅ Modern Browsers
  - ✅ Node 18+ (WebCrypto)
- 💡 Fully tree-shakable

---

## 📦 Install

```bash
npm install pw-punch
```

---

## 🔧 API Usage

### 🔒 Hash a password

```ts
import { hashPassword } from 'pw-punch'

const hashed = await hashPassword('hunter2')
// "base64salt:base64hash"
```

### ✅ Verify a password

```ts
import { verifyPassword } from 'pw-punch'

const isValid = await verifyPassword('hunter2', hashed)
// true or false
```

### ✍️ Sign a token

```ts
import { signToken } from 'pw-punch'

// Generate RSA key pair first
const keyPair = await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
  },
  true,
  ['sign', 'verify']
)

const token = await signToken(keyPair.privateKey, { sub: 'user' }, { kid: 'key-1' })
```

### 🕵️ Verify a token

```ts
import { verifyToken } from 'pw-punch'

const payload = await verifyToken(token, keyPair.publicKey)
// returns payload or null
```

### 🔍 Decode token (without verifying)

```ts
import { decodeToken } from 'pw-punch'

const { header, payload, signature } = decodeToken(token)
```

---

## 📘 Full Example

```ts
// Generate RSA key pair
const keyPair = await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
  },
  true,
  ['sign', 'verify']
)

// Sign token with minimal header (recommended)
const token = await signToken(keyPair.privateKey, { sub: 'user' })

// Sign token with key rotation
const tokenWithKid = await signToken(keyPair.privateKey, { sub: 'user' }, { kid: 'key-v1' })

// Sign token without typ field (shorter)
const shortToken = await signToken(keyPair.privateKey, { sub: 'user' }, { includeTyp: false })

// Verify token
const payload = await verifyToken(token, keyPair.publicKey)
```

---

## 🔐 Security Guidelines

### 🔑 Key Management Best Practices

- **Key Size**: Use minimum 2048-bit RSA keys (4096-bit recommended for high security)
- **Key Rotation**: Rotate keys regularly and use `kid` field for versioning
- **Key Storage**: Never store private keys in client-side code
- **Key Generation**: Use crypto.subtle.generateKey() for secure random generation

```ts
// ✅ Good: Strong key generation
const keyPair = await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 4096, // Strong key size
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
  },
  false, // Non-extractable for security
  ['sign', 'verify']
)
```

### ⏰ Token Expiration Guidelines

- **Short-lived tokens**: 15 minutes to 1 hour for high-security APIs
- **Regular tokens**: 1-24 hours for standard applications
- **Refresh strategy**: Use refresh tokens for longer sessions

```ts
// ✅ Good: Appropriate expiration times
const now = Math.floor(Date.now() / 1000)
const payload = {
  sub: 'user123',
  iat: now,
  exp: now + 3600, // 1 hour expiration
  nbf: now // Valid from now
}
```

### 🛡️ Validation Best Practices

```ts
// ✅ Good: Custom validation with security checks
const payload = await verifyToken(token, publicKey, (claims) => {
  // Check issuer
  if (claims.iss !== 'trusted-issuer') return false
  
  // Check audience
  if (!claims.aud?.includes('my-api')) return false
  
  // Check custom claims
  if (claims.role !== 'admin' && claims.action === 'delete') return false
  
  return true
})
```

---

## 📖 API Reference

### `hashPassword(password, type?, iterations?)`

Hashes a password using PBKDF2 with SHA-256 or SHA-512.

**Parameters:**

- `password` (string): Plain-text password to hash
- `type` (256 | 512): Hash algorithm. Default: 256
- `iterations` (number): PBKDF2 iterations. Default: 150,000

**Returns:** `Promise<string>` - Base64-encoded "salt:hash"

### `verifyPassword(password, hashed, type?, iterations?)`

Verifies a password against a PBKDF2 hash.

**Parameters:**

- `password` (string): Plain-text password to verify
- `hashed` (string): Stored hash from hashPassword()
- `type` (256 | 512): Hash algorithm. Default: 256
- `iterations` (number): PBKDF2 iterations. Default: 150,000

**Returns:** `Promise<boolean>` - True if password matches

### `signToken(privateKey, payload, options?)`

Signs a JWT token using RS256.

**Parameters:**

- `privateKey` (CryptoKey): RSA private key for signing
- `payload` (TokenPayload): JWT payload with claims
- `options` (object, optional):
  - `kid` (string): Key ID for key rotation
  - `includeTyp` (boolean): Include "typ: JWT" header. Default: true

**Returns:** `Promise<string>` - Signed JWT token

### `verifyToken(token, publicKey, customValidate?)`

Verifies and decodes a JWT token.

**Parameters:**

- `token` (string): JWT token to verify
- `publicKey` (CryptoKey): RSA public key for verification
- `customValidate` (function, optional): Custom validation function

**Returns:** `Promise<TokenPayload | null>` - Decoded payload or null if invalid

### `decodeToken(token)`

Decodes a JWT token without verification (for inspection only).

**Parameters:**

- `token` (string): JWT token to decode

**Returns:** `{header, payload, signature}` - Decoded parts or null if invalid

---

## 🧪 Tests & Demo

- ✅ All core features tested using [`bun test`](https://bun.sh/docs/test)
- ✅ Additional **interactive demo** available:

```bash
npm run demo
```

Select and run hashing/token functions in CLI with colored output.
Great for dev previewing & inspection.

---

## 📦 Built With

- 🌀 100% WebCrypto (FIPS-compliant)
- ⚡ Bun for test/dev (optional)
- 📐 TypeScript + `tsc` build
- 🔬 No dependencies at all

---

## ⚠️ Disclaimer

This is **not a full JWT spec implementation**.

- Only `RS256` is supported (no HMAC/EC)
- You must check claims like `aud`, `iss` yourself, or provide a `customValidate()` hook
- No support for JWE/JWS standards
- RSA key pair management is up to the user

---

## 🔮 Roadmap

- [x] Interactive CLI demo
- [x] JWT claim validation hook

This is the way.

---

## 📄 License

MIT

---

<!-- keywords: jwt, token, rsa, rs256, pbkdf2, crypto, webcrypto, edge, serverless, cloudflare, bun, vercel, deno, browser, password, hashing, lightweight, 0dep, zero-dependency -->

