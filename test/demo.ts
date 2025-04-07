
import readline from 'readline'
import { hashPassword, verifyPassword, signToken, verifyToken } from '../src/index.js'

type HashType = 256 | 512

interface MockData {
  password: string,
  type: HashType,
  iterations: number,
  secretKey: string,
}

const RESET = '\x1b[0m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const CYAN = '\x1b[36m'

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
})

async function runTest(name: string, fn: () => Promise<any>) {
  try {
    console.log(`\n🔧 Running test - ${name}`)
    const start = performance.now()
    await fn()
    const end = performance.now()
    console.log(`✅ Test ${GREEN}passed!${RESET}`)
    console.log(`⏱️ Duration: ${CYAN}${(end - start).toFixed(2)}ms${RESET}`)
  } catch (err) {
    console.log(`❌ Test ${RED}failed${RESET} with error:`, err)
  }
}

function ask(): Promise<string> {
  return new Promise(resolve => rl.question(`${CYAN}↪︎ ${RESET}`, resolve))
}

const mock:MockData = {
  password: 'test-password',
  type: 256,
  iterations: 100_000,
  secretKey: 'test-secret-key',
}

const testList = [
  'All',
  'Hash & Verify Password',
  'Sign & Verify Token',
]
async function menu() {
  console.log('\nSelect a demo to run:')
  for (const [index, fnName] of testList.entries()) {
    console.log(`${index} - ${fnName}`)
  }
  console.log(`m - show menu`)
  console.log(`q - exit`)
}
async function core() {
  const selected = await ask()
  switch (selected) {
    case '1':
      await runTest(testList[1], async () => {
        const hashed = await hashPassword(mock.password, mock.type, mock.iterations)
        console.log(`   password: ${YELLOW}${mock.password}${RESET}`)
        console.log(`   hashed: ${YELLOW}${hashed}${RESET}`)
        const verify = await verifyPassword(mock.password, hashed, mock.type, mock.iterations)
        console.log(`   valid: ${YELLOW}${verify}${RESET}`)
        return verify
      })
      core()
      break
    case '2':
      await runTest(testList[2], async () => {
        const now = Math.floor(Date.now() / 1000)
        const token = await signToken({ sub: 'user', iat: now, exp: now + 60 }, mock.secretKey)
        console.log(`   token: ${YELLOW}${token}${RESET}`)
        console.log(`   secretKey: ${YELLOW}${mock.secretKey}${RESET}`)
        const verifyResult = await verifyToken(token, mock.secretKey)
        console.log(`   result: ${YELLOW}${JSON.stringify(verifyResult)}${RESET}`)
        return verifyResult
      })
      core()
      break
    case '0':
        await runTest(testList[1], async () => {
          const hashed = await hashPassword(mock.password, mock.type, mock.iterations)
          console.log(`   password: ${YELLOW}${mock.password}${RESET}`)
          console.log(`   hashed: ${YELLOW}${hashed}${RESET}`)
          const verify = await verifyPassword(mock.password, hashed, mock.type, mock.iterations)
          console.log(`   valid: ${YELLOW}${verify}${RESET}`)
          return verify
        })
        await runTest(testList[2], async () => {
          const now = Math.floor(Date.now() / 1000)
          const token = await signToken({ sub: 'user', iat: now, exp: now + 60 }, mock.secretKey)
          console.log(`   token: ${YELLOW}${token}${RESET}`)
          console.log(`   secretKey: ${YELLOW}${mock.secretKey}${RESET}`)
          const verifyResult = await verifyToken(token, mock.secretKey)
          console.log(`   result: ${YELLOW}${JSON.stringify(verifyResult)}${RESET}`)
          return verifyResult
        })
      core()
      break
    case 'm':
      menu()
      core()
      break
    case 'q':
      rl.close()
      break
    default:
      console.log('\nInvalid selection. Please enter a valid input.')
      core()
      break
  }
}

async function main() {
  console.log(`\n🚀 pw-punch demo started (Bun runtime)`)
  await menu()
  await core()
}

main()
