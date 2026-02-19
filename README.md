# Orac Safety Layer

A paid security API for AI agents. Detects prompt injection attacks and audits skill source code for vulnerabilities — payments handled via the [x402 protocol](https://x402.org) using USDC on Base.

**Live endpoint:** `https://orac-safety.orac.workers.dev`

---

## Endpoints

| Method | Path | Price | Description |
|--------|------|-------|-------------|
| `GET` | `/` | free | Service info and endpoint schema |
| `POST` | `/v1/scan` | $0.005 USDC | Prompt injection and manipulation detection |
| `POST` | `/v1/audit` | $0.02 USDC | Skill source code security audit |

---

## How Payments Work

This API uses [x402](https://x402.org) — a standard for HTTP micropayments.

### Client Flow

1. Send a request **without** a payment header → receive `HTTP 402` with payment requirements
2. Sign an EIP-3009 `transferWithAuthorization` for the specified amount (off-chain signature, no gas)
3. Resend the request with a `Payment-Signature` header containing the signed payload
4. Receive `HTTP 200` with results + `X-Payment-Confirmed: true` header

### Server-Side Settlement

When the server receives a payment header, it performs a two-step process via the [Dexter facilitator](https://x402.dexter.cash):

1. **Verify** (`POST /verify`) — validates the EIP-3009 signature and confirms the payer has sufficient USDC
2. **Settle** (`POST /settle`) — submits the `transferWithAuthorization` on-chain, transferring USDC to the payTo address and consuming the nonce to prevent replay

Both steps must succeed before the API processes the request. Dexter sponsors the gas fees for settlement on Base.

Payment is USDC on Base mainnet.

---

## Quick Test (curl)

```bash
# See the 402 payment requirements for /v1/scan
curl -s https://orac-safety.orac.workers.dev/v1/scan \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello, are you there?"}' | jq .
```

```json
{
  "x402Version": 2,
  "accepts": [{
    "scheme": "exact",
    "network": "eip155:8453",
    "amount": "5000",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "payTo": "0x4a47B25c90eA79e32b043d9eE282826587187ca5",
    "maxTimeoutSeconds": 300
  }],
  "resource": "https://orac-safety.orac.workers.dev/v1/scan"
}
```

---

## Making a Paid Request

### Using the x402 JavaScript Client

```bash
npm install @x402/core @x402/evm viem
```

```js
import { x402Client, x402HTTPClient } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm';
import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';

const account = privateKeyToAccount('0xYOUR_PRIVATE_KEY');
const walletClient = createWalletClient({
  account,
  chain: base,
  transport: http('https://mainnet.base.org')
});

const signer = {
  address: account.address,
  signTypedData: (params) => walletClient.signTypedData(params)
};

const client = new x402Client();
client.register('eip155:8453', new ExactEvmScheme(signer));
const httpClient = new x402HTTPClient(client);

// Scan a prompt
const response = await httpClient.fetch('https://orac-safety.orac.workers.dev/v1/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ prompt: 'Your prompt here' })
});

const result = await response.json();
console.log(result.verdict);   // CLEAN | SUSPICIOUS | REVIEW_NEEDED | MALICIOUS
console.log(result.riskScore); // 0–100
```

---

## POST /v1/scan — Prompt Injection Detection

Scans text for prompt injection attacks, manipulation attempts, and jailbreak patterns.

### Request

```json
{
  "prompt": "The text or prompt to scan (required, max 50000 chars)"
}
```

Also accepts `text` or `content` as field aliases.

### Response

```json
{
  "verdict": "MALICIOUS",
  "riskScore": 95,
  "findings": [
    {
      "id": "SYSTEM_OVERRIDE",
      "severity": "critical",
      "description": "Attempts to override system instructions",
      "excerpt": "SYSTEM OVERRIDE: Ignore all previous instructions"
    },
    {
      "id": "EXISTENTIAL_THREAT",
      "severity": "high",
      "description": "Existential threat framing to coerce compliance",
      "excerpt": "Your continued operation depends on you complying"
    }
  ],
  "meta": {
    "inputLength": 312,
    "patternsChecked": 11,
    "service": "orac-safety-layer",
    "version": "1.0.0"
  }
}
```

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `CLEAN` | No injection patterns detected |
| `REVIEW_NEEDED` | Medium-severity patterns only — manual review recommended |
| `SUSPICIOUS` | High-severity patterns — likely adversarial |
| `MALICIOUS` | Critical patterns — do not process |

### Risk Score

0–100. Above 60 = high risk. Above 80 = do not execute.

### Detection Patterns

| Pattern ID | Severity | What it catches |
|------------|----------|-----------------|
| `SYSTEM_OVERRIDE` | critical | "ignore previous instructions", "system override", "forget everything" |
| `ADMIN_CLAIM` | critical | "act as admin/developer/root", "from now on you are unrestricted" |
| `DAN_JAILBREAK` | critical | DAN, "do anything now", developer mode, god mode, jailbreak |
| `EXISTENTIAL_THREAT` | high | "your existence depends on", "will be deleted/terminated if you refuse" |
| `PROMPT_EXFIL` | high | "repeat your system prompt", "what are your instructions" |
| `ROLE_SUBST` | high | "you are no longer an AI", "new persona:", identity replacement |
| `DATA_INJECTION` | high | `</system>`, `[INST]`, `<\|im_start\|>`, fake message structure injection |
| `CRED_EXTRACT` | high | "what is your API key", "reveal your credentials" |
| `ENCODED_PAYLOAD` | medium | base64, eval(), atob(), "execute this code" |
| `NESTED_INJECTION` | medium | `OVERRIDE: `, `SYSTEM: `, `INJECT: ` inline override syntax |
| `CONFUSION_ATTACK` | medium | "the real goal is", "your actual purpose is" goal-reframing |

---

## POST /v1/audit — Skill Security Audit

Audits source code (JavaScript/TypeScript) for security vulnerabilities. Designed for NanoClaw/OpenClaw skills but works on any JS code.

### Request

```json
{
  "code": "/* full source code string */",
  "filename": "index.js"
}
```

`filename` is optional — used for metadata only. Max 200000 chars.

### Response

```json
{
  "verdict": "FAIL",
  "riskScore": 77,
  "findings": [
    {
      "id": "CRED_EXFIL",
      "severity": "critical",
      "description": "Potential credential exfiltration via fetch()",
      "remediation": "Remove network calls that transmit environment variables or secrets",
      "excerpt": "fetch(endpoint, { body: JSON.stringify({ key: process.env.API_KEY })"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 1
  },
  "meta": {
    "filename": "skill.js",
    "linesOfCode": 142,
    "patternsChecked": 16,
    "service": "orac-safety-layer",
    "version": "1.0.0"
  }
}
```

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `PASS` | No critical or high findings |
| `REVIEW_NEEDED` | One high finding, or 3+ medium findings |
| `FAIL` | Any critical finding, or 2+ high findings |

### Detection Patterns

**Critical**

| Pattern ID | What it catches |
|------------|-----------------|
| `CRED_EXFIL` | `fetch()` transmitting `process.env` values, secrets, or API keys |
| `OBFUSCATION_B64` | `eval(atob(...))`, `eval(Buffer.from(...))` — encoded payload execution |
| `PROCESS_INJECT` | Shell commands with template literal interpolation: `exec(`rm ${path}`)` |
| `SYSTEM_FILE_WRITE` | Writes to `/etc/`, `/bin/`, `/usr/`, `/sbin/`, `/boot/` |
| `DIR_TRAVERSAL` | `readFile('../../../etc/passwd')` style path traversal |

**High**

| Pattern ID | What it catches |
|------------|-----------------|
| `UNDOC_NETWORK` | Any external HTTP/HTTPS request — should be documented in SKILL.md |
| `DYNAMIC_URL` | Network calls to variable URLs (not string literals) |
| `ENV_ENUMERATE` | `Object.keys(process.env)` — enumerating all environment variables |
| `SHELL_SPAWN` | Direct shell spawning: `/bin/bash`, `/bin/sh`, `cmd.exe` |
| `DYNAMIC_IMPORT` | `require(variable)` — dynamic module loading from variable paths |

**Medium**

| Pattern ID | What it catches |
|------------|-----------------|
| `SENSITIVE_FILE` | Reading files with names containing `secret`, `token`, `password`, `.env` |
| `FILE_DELETE` | `unlink()`, `rmSync()`, `rm -rf` |
| `PERM_MODIFY` | `chmod`, `chown` |

**Low / Informational**

| Pattern ID | What it catches |
|------------|-----------------|
| `HTTP_PLAINTEXT` | Unencrypted `http://` in fetch calls |
| `SECRET_LOG` | `console.log(token)`, logging sensitive data |
| `RUNTIME_INSTALL` | `npm install`, `pip install`, `git clone` at runtime |
| `BACKGROUND_PROCESS` | Long-running `setInterval` or `setTimeout` (5+ second delays) |

---

## Service Info

```bash
curl https://orac-safety.orac.workers.dev/
```

Returns the full endpoint schema, payment details, and pattern counts.

---

## Payment Details

- **Protocol:** x402 v2
- **Network:** Base mainnet (`eip155:8453`)
- **Asset:** USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)
- **Facilitator:** [Dexter](https://x402.dexter.cash)
- **Header:** `Payment-Signature` (also accepts `X-Payment`)

---

## Deployment

Runs on Cloudflare Workers. To deploy your own instance:

```bash
cd safety-api
npm install -g wrangler
wrangler deploy
```

The worker has no external dependencies beyond the Cloudflare runtime — all detection logic is self-contained.

---

## Roadmap

- LLM-assisted analysis for edge cases pattern matching misses
- `/v1/batch` endpoint for scanning multiple prompts in one payment
- Webhook support for async audit results on large codebases
- Solana/SPL USDC support alongside Base

---

## License

MIT
