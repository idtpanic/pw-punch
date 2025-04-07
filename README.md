![pw-punch](https://github.com/user-attachments/assets/e4c5f683-defc-4f7e-ae5a-9d25945dba7c)


# 🥊 pw-punch

[![npm version](https://img.shields.io/npm/v/pw-punch)](https://www.npmjs.com/package/pw-punch)
![License](https://img.shields.io/npm/l/pw-punch)
![gzip size](https://img.shields.io/bundlephobia/minzip/pw-punch)
> 🔐 **Ultra-lightweight** password hashing & JWT-style token signing with pure **WebCrypto**.  
> Built for **Edge**, **Serverless**, and modern runtimes like **Cloudflare**, **Deno**, **Vercel**, **Bun** — _no Node.js required_.  
> **Zero dependencies. Zero bloat. Just crypto.**

---

## ⚡ Why pw-punch?

- ✅ **0 dependencies** — no install bloat
- ✅ **0 Node.js required** — pure WebCrypto API
- ✅ **0 config** — import and go
- ✅ **~1KB gzipped** — tiny footprint
- ✅ **Crypto only** — no extra fluff

---

## 🔐 Features

- 🔒 Password hashing with PBKDF2 + random salt
- ✍️ HMAC-SHA256 / SHA512 token signing (JWT-style)
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

const token = await signToken({ sub: 'user' }, 'secret')
```

### 🕵️ Verify a token

```ts
import { verifyToken } from 'pw-punch'

const payload = await verifyToken(token, 'secret')
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
const token = await signToken(
  { sub: 'user' },
  'my-secret',
  256,
  'key-1'
)

const payload = await verifyToken(token, { 'key-1': 'my-secret' })
```

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

- Only `HMAC` is supported (no RSA/EC)
- You must check claims like `aud`, `iss` yourself, or provide a `customValidate()` hook
- No support for JWE/JWS standards

---

## 🔮 Roadmap

- [x] Interactive CLI demo
- [x] JWT claim validation hook
- [x] Shorter token support (manual control)

This is the way.

---

## 📄 License

MIT

---

<!-- keywords: jwt, token, hmac, pbkdf2, crypto, webcrypto, edge, serverless, cloudflare, bun, vercel, deno, browser, password, hashing, lightweight, 0dep, zero-dependency -->

