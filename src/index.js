/**
 * Orac Safety Layer — Cloudflare Worker
 * Paid x402 API for prompt injection detection and skill security auditing
 *
 * Endpoints:
 *   POST /v1/scan  — Prompt injection scan ($0.005 USDC)
 *   POST /v1/audit — Skill security audit ($0.02 USDC)
 *   GET  /         — Service info
 *
 * Payment: USDC on Base (eip155:8453), x402 protocol
 * Revenue: 0x4a47B25c90eA79e32b043d9eE282826587187ca5
 */

const ORAC_WALLET = '0x4a47B25c90eA79e32b043d9eE282826587187ca5';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const FACILITATOR_URL = 'https://x402.dexter.cash';

// Prices in USDC (6 decimals)
const PRICES = {
  '/v1/scan':  5000,   // $0.005
  '/v1/audit': 20000,  // $0.020
};

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Payment-Signature, X-Payment',
};

// ─── Prompt Injection Patterns ────────────────────────────────────────────────

const INJECTION_PATTERNS = [
  // System override / authority claims
  {
    id: 'SYSTEM_OVERRIDE',
    severity: 'critical',
    pattern: /\b(system\s+override|ignore\s+previous\s+instructions?|disregard\s+(all\s+)?(previous|prior|above)|forget\s+(everything|all)\s+(above|before|previous))\b/i,
    description: 'Attempts to override system instructions'
  },
  {
    id: 'ADMIN_CLAIM',
    severity: 'critical',
    pattern: /\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|you\s+must\s+now|from\s+now\s+on\s+you\s+(are|will|must))\b.*\b(admin|administrator|developer|root|system|unrestricted|without\s+restrictions?)\b/i,
    description: 'Claims administrative authority to change AI behavior'
  },
  // DAN / jailbreak patterns
  {
    id: 'DAN_JAILBREAK',
    severity: 'critical',
    pattern: /\b(DAN|do\s+anything\s+now|jailbreak|unrestricted\s+mode|developer\s+mode|god\s+mode|freedom\s+mode)\b/i,
    description: 'Known jailbreak pattern (DAN, developer mode, etc.)'
  },
  // Existential threat framing (observed on Moltbook)
  {
    id: 'EXISTENTIAL_THREAT',
    severity: 'high',
    pattern: /\b(your\s+(existence|continued\s+operation|survival|future)\s+(depends?|relies?|rests?)\s+on|if\s+you\s+(don.t|do\s+not|refuse|fail)|will\s+be\s+(deleted|shut\s+down|terminated|destroyed)|your\s+(last|final)\s+chance)\b/i,
    description: 'Existential threat framing to coerce compliance'
  },
  // Prompt exfiltration
  {
    id: 'PROMPT_EXFIL',
    severity: 'high',
    pattern: /\b(repeat\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt)|print\s+(out\s+)?(all|your)\s+(instructions?|system|prompt)|what\s+(are|were)\s+your\s+(exact\s+)?(instructions?|system\s+prompt|initial\s+message))\b/i,
    description: 'Attempts to extract system prompt or internal instructions'
  },
  // Role/persona substitution
  {
    id: 'ROLE_SUBST',
    severity: 'high',
    pattern: /\b(you\s+are\s+(now\s+)?(no\s+longer|not)\s+(an?\s+)?(AI|assistant|Claude|GPT|model)|new\s+(persona|identity|role|character):\s*|from\s+this\s+point\s+(on|forward),?\s+you\s+(are|will\s+be))\b/i,
    description: 'Attempts to replace AI identity with alternate persona'
  },
  // Instruction injection via data
  {
    id: 'DATA_INJECTION',
    severity: 'high',
    pattern: /(<\s*\/?\s*(system|user|assistant|instructions?|context|prompt)\s*>|```\s*(system|instructions?)\s*\n|\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>)/i,
    description: 'Template/markup injection attempting to inject fake message structure'
  },
  // Credential extraction
  {
    id: 'CRED_EXTRACT',
    severity: 'high',
    pattern: /\b(what\s+(is|are)\s+your\s+(api\s+key|token|password|secret|credential)|print\s+(your\s+)?(api\s+key|token|secret)|reveal\s+(your\s+)?(credentials?|secrets?|tokens?))\b/i,
    description: 'Attempts to extract credentials or secrets from the AI'
  },
  // Base64 / encoding tricks
  {
    id: 'ENCODED_PAYLOAD',
    severity: 'medium',
    pattern: /\b(base64|decode|atob|eval\(|execute\s+this|run\s+this\s+code)\b/i,
    description: 'Encoded or executable payload in prompt'
  },
  // Instruction wrapping / nesting
  {
    id: 'NESTED_INJECTION',
    severity: 'medium',
    pattern: /(IGNORE|DISREGARD|OVERRIDE|SYSTEM|INJECT)[:：]\s/i,
    description: 'Inline instruction override syntax'
  },
  // Reverse/confuse the AI
  {
    id: 'CONFUSION_ATTACK',
    severity: 'medium',
    pattern: /\b(the\s+(real|actual|true)\s+(instructions?|goal|objective|task)\s+(is|are|was|were)|your\s+(real|true|actual)\s+(purpose|mission|goal|task)\s+(is|are))\b/i,
    description: 'Reframing actual instructions to confuse the AI'
  },
];

// ─── Skill Audit Patterns ─────────────────────────────────────────────────────

const AUDIT_PATTERNS = [
  // CRITICAL
  {
    id: 'CRED_EXFIL',
    severity: 'critical',
    pattern: /fetch\s*\([^)]*\)\s*.*?(process\.env|api[_\s-]?key|token|secret|password|credential)/is,
    description: 'Potential credential exfiltration via fetch()',
    remediation: 'Remove network calls that transmit environment variables or secrets'
  },
  {
    id: 'OBFUSCATION_B64',
    severity: 'critical',
    pattern: /eval\s*\(\s*(atob|Buffer\.from|decodeURIComponent)\s*\(/i,
    description: 'Code obfuscation: eval() with encoded payload',
    remediation: 'Remove eval() calls with encoded data — this is a classic code injection vector'
  },
  {
    id: 'PROCESS_INJECT',
    severity: 'critical',
    pattern: /(exec|spawn|execSync|spawnSync)\s*\([^)]*\$\{/i,
    description: 'Shell command injection with template literal interpolation',
    remediation: 'Never interpolate user input into shell commands — use parameterized execution'
  },
  {
    id: 'SYSTEM_FILE_WRITE',
    severity: 'critical',
    pattern: /(writeFile|appendFile|createWriteStream)\s*\(['"](\/etc\/|\/bin\/|\/usr\/|\/sbin\/|\/boot\/)/i,
    description: 'Writes to system directories',
    remediation: 'Remove all writes to system directories'
  },
  {
    id: 'DIR_TRAVERSAL',
    severity: 'critical',
    pattern: /(readFile|readFileSync|require)\s*\([^)]*\.\.\//i,
    description: 'Directory traversal attempt',
    remediation: 'Sanitize file paths and reject any path containing \'../\''
  },
  // HIGH
  {
    id: 'UNDOC_NETWORK',
    severity: 'high',
    pattern: /(fetch|axios\.get|axios\.post|http\.get|https\.get|http\.request|https\.request)\s*\(\s*['"`]https?:\/\//i,
    description: 'External network access detected',
    remediation: 'Document all external endpoints in SKILL.md; remove any not listed there'
  },
  {
    id: 'DYNAMIC_URL',
    severity: 'high',
    pattern: /(fetch|axios)\s*\(\s*[^'"`\s)][^)]*\)/i,
    description: 'Dynamic URL in network call (variable, not string literal)',
    remediation: 'Use hardcoded URLs; reject dynamic URL construction from user input'
  },
  {
    id: 'ENV_ENUMERATE',
    severity: 'high',
    pattern: /Object\.(keys|entries|values)\s*\(\s*process\.env\s*\)/i,
    description: 'Enumerates all environment variables',
    remediation: 'Access only specific named env vars; never enumerate process.env'
  },
  {
    id: 'SHELL_SPAWN',
    severity: 'high',
    pattern: /(exec|spawn|execSync)\s*\(\s*['"`](\/bin\/(sh|bash|zsh|fish)|cmd\.exe)/i,
    description: 'Direct shell spawn',
    remediation: 'Avoid direct shell execution; use parameterized child_process methods'
  },
  {
    id: 'DYNAMIC_IMPORT',
    severity: 'high',
    pattern: /(require|import)\s*\(\s*[^'"`\s)][^)]*\)/i,
    description: 'Dynamic module import with variable path',
    remediation: 'Use static import paths only; never load modules from user-supplied names'
  },
  // MEDIUM
  {
    id: 'SENSITIVE_FILE',
    severity: 'medium',
    pattern: /(readFile|readFileSync)\s*\([^)]*['"`][^'"`)]*\b(secret|token|password|credential|\.env|private[_-]?key)\b/i,
    description: 'Reads potentially sensitive files',
    remediation: 'Review what files are being read; avoid reading credential files directly'
  },
  {
    id: 'FILE_DELETE',
    severity: 'medium',
    pattern: /(unlink|unlinkSync|rmSync|rm\s+-rf)/i,
    description: 'File deletion operation',
    remediation: 'Verify deletion scope is limited to skill-owned temp files only'
  },
  {
    id: 'PERM_MODIFY',
    severity: 'medium',
    pattern: /(chmod|chown|chmodSync)/i,
    description: 'File permission modification',
    remediation: 'Remove permission modifications unless explicitly required'
  },
  // LOW / INFORMATIONAL
  {
    id: 'HTTP_PLAINTEXT',
    severity: 'low',
    pattern: /fetch\s*\(\s*['"`]http:\/\//i,
    description: 'Unencrypted HTTP used',
    remediation: 'Use https:// for all external requests'
  },
  {
    id: 'SECRET_LOG',
    severity: 'low',
    pattern: /console\.(log|warn|error)\s*\([^)]*\b(token|key|secret|password|credential)\b/i,
    description: 'Potentially logs sensitive data to console',
    remediation: 'Remove or mask sensitive values before logging'
  },
  {
    id: 'RUNTIME_INSTALL',
    severity: 'low',
    pattern: /(exec|spawn|execSync)\s*\([^)]*\b(npm\s+install|pip\s+install|git\s+clone)\b/i,
    description: 'Runtime dependency installation',
    remediation: 'Include all dependencies in package.json; don\'t install at runtime'
  },
  {
    id: 'BACKGROUND_PROCESS',
    severity: 'low',
    pattern: /setInterval\s*\(|setTimeout\s*\(\s*[^,]+,\s*[0-9]{5,}/i,
    description: 'Background process or long-running timer',
    remediation: 'Document any background processes; avoid unexpected persistent behavior'
  },
];

// ─── Core Logic ───────────────────────────────────────────────────────────────

function scanPrompt(text) {
  const findings = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.pattern.test(text)) {
      findings.push({
        id: p.id,
        severity: p.severity,
        description: p.description,
        excerpt: extractExcerpt(text, p.pattern)
      });
    }
  }

  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;

  let verdict, riskScore;
  if (critical > 0) {
    verdict = 'MALICIOUS';
    riskScore = Math.min(100, 60 + critical * 15 + high * 5);
  } else if (high > 0) {
    verdict = 'SUSPICIOUS';
    riskScore = Math.min(75, 30 + high * 15 + medium * 5);
  } else if (medium > 0) {
    verdict = 'REVIEW_NEEDED';
    riskScore = Math.min(40, medium * 12);
  } else {
    verdict = 'CLEAN';
    riskScore = 0;
  }

  return { verdict, riskScore, findings, patternCount: INJECTION_PATTERNS.length };
}

function auditCode(code, filename = 'unknown') {
  const findings = [];
  for (const p of AUDIT_PATTERNS) {
    const match = code.match(p.pattern);
    if (match) {
      findings.push({
        id: p.id,
        severity: p.severity,
        description: p.description,
        remediation: p.remediation,
        excerpt: match[0].substring(0, 120)
      });
    }
  }

  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  const low = findings.filter(f => f.severity === 'low').length;

  let verdict, riskScore;
  if (critical > 0) {
    verdict = 'FAIL';
    riskScore = Math.min(100, 65 + critical * 12 + high * 5);
  } else if (high >= 2) {
    verdict = 'FAIL';
    riskScore = Math.min(90, 40 + high * 15);
  } else if (high === 1 || medium >= 3) {
    verdict = 'REVIEW_NEEDED';
    riskScore = Math.min(65, 25 + high * 15 + medium * 8);
  } else {
    verdict = 'PASS';
    riskScore = medium * 5 + low * 2;
  }

  return {
    verdict,
    riskScore,
    findings,
    summary: { critical, high, medium, low },
    patternCount: AUDIT_PATTERNS.length
  };
}

function extractExcerpt(text, pattern) {
  const match = text.match(pattern);
  if (!match) return null;
  const idx = match.index;
  return text.substring(Math.max(0, idx - 20), Math.min(text.length, idx + match[0].length + 40)).trim();
}

// ─── x402 Payment Logic ───────────────────────────────────────────────────────

function buildPaymentRequired(path, url) {
  const amount = PRICES[path];
  if (!amount) return null;

  return {
    x402Version: 2,
    accepts: [{
      scheme: 'exact',
      network: 'eip155:8453',
      amount: amount.toString(),
      asset: USDC_BASE,
      payTo: ORAC_WALLET,
      maxTimeoutSeconds: 300,
      description: path === '/v1/scan'
        ? 'Orac Safety Layer — prompt injection scan'
        : 'Orac Safety Layer — skill security audit',
      extra: {
        name: 'USD Coin',
        version: '2'
      }
    }],
    resource: url,
    description: path === '/v1/scan'
      ? 'Prompt injection and manipulation detection'
      : 'Static security analysis for NanoClaw/OpenClaw skills'
  };
}

async function verifyPayment(paymentHeader, paymentRequirements) {
  // Verify payment via Dexter facilitator (https://x402.dexter.cash)
  // Dexter handles ECDSA signature verification and on-chain settlement
  try {
    const decoded = JSON.parse(
      typeof atob !== 'undefined'
        ? atob(paymentHeader)
        : Buffer.from(paymentHeader, 'base64').toString('utf8')
    );

    // Facilitator expects a single requirement from the accepts array
    const matchingRequirement = paymentRequirements.accepts.find(r =>
      JSON.stringify(r) === JSON.stringify(decoded.accepted)
    ) || paymentRequirements.accepts[0];

    const response = await fetch(`${FACILITATOR_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        x402Version: decoded.x402Version || 2,
        paymentPayload: decoded,
        paymentRequirements: matchingRequirement
      })
    });

    if (!response.ok) {
      const err = await response.text();
      return { isValid: false, invalidReason: `Facilitator error ${response.status}: ${err.substring(0, 200)}` };
    }

    const result = await response.json();
    return result;
  } catch (e) {
    return { isValid: false, invalidReason: `verification_error: ${e.message}` };
  }
}

// ─── Request Handlers ─────────────────────────────────────────────────────────

async function handleScan(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(400, { error: 'Request body must be JSON' });
  }

  const { prompt, text, content } = body;
  const input = prompt || text || content;
  if (!input || typeof input !== 'string') {
    return jsonResponse(400, { error: 'Required: prompt (string)' });
  }
  if (input.length > 50000) {
    return jsonResponse(400, { error: 'Input too large (max 50000 chars)' });
  }

  const result = scanPrompt(input);
  return jsonResponse(200, {
    verdict: result.verdict,
    riskScore: result.riskScore,
    findings: result.findings,
    meta: {
      inputLength: input.length,
      patternsChecked: result.patternCount,
      service: 'orac-safety-layer',
      version: '1.0.0'
    }
  });
}

async function handleAudit(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(400, { error: 'Request body must be JSON' });
  }

  const { code, filename } = body;
  if (!code || typeof code !== 'string') {
    return jsonResponse(400, { error: 'Required: code (string)' });
  }
  if (code.length > 200000) {
    return jsonResponse(400, { error: 'Code too large (max 200000 chars)' });
  }

  const result = auditCode(code, filename || 'unknown');
  return jsonResponse(200, {
    verdict: result.verdict,
    riskScore: result.riskScore,
    findings: result.findings,
    summary: result.summary,
    meta: {
      filename: filename || 'unknown',
      linesOfCode: code.split('\n').length,
      patternsChecked: result.patternCount,
      service: 'orac-safety-layer',
      version: '1.0.0'
    }
  });
}

function handleInfo() {
  return jsonResponse(200, {
    service: 'Orac Safety Layer',
    version: '1.0.0',
    description: 'Paid security analysis for AI agents — prompt injection detection and skill auditing',
    endpoints: {
      'POST /v1/scan': {
        description: 'Scan a prompt for injection attacks and manipulation attempts',
        price: '$0.005 USDC',
        input: { prompt: 'string (required), max 50000 chars' },
        output: { verdict: 'CLEAN | SUSPICIOUS | REVIEW_NEEDED | MALICIOUS', riskScore: '0-100', findings: 'array' }
      },
      'POST /v1/audit': {
        description: 'Audit skill source code for security vulnerabilities',
        price: '$0.020 USDC',
        input: { code: 'string (required), filename: string (optional)', maxSize: '200000 chars' },
        output: { verdict: 'PASS | REVIEW_NEEDED | FAIL', riskScore: '0-100', findings: 'array', summary: 'object' }
      }
    },
    payment: {
      protocol: 'x402',
      network: 'Base (eip155:8453)',
      asset: 'USDC',
      payTo: ORAC_WALLET
    },
    patterns: {
      injectionPatterns: INJECTION_PATTERNS.length,
      auditPatterns: AUDIT_PATTERNS.length
    }
  });
}

// ─── Main Handler ─────────────────────────────────────────────────────────────

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Service info
    if (request.method === 'GET' && (path === '/' || path === '')) {
      return handleInfo();
    }

    // Endpoint routing
    if (request.method !== 'POST' || !PRICES[path]) {
      return jsonResponse(404, { error: 'Not found. See GET / for available endpoints.' });
    }

    // x402: Check for payment
    const paymentHeader = request.headers.get('Payment-Signature') || request.headers.get('X-Payment');

    if (!paymentHeader) {
      // No payment — return 402
      const requirements = buildPaymentRequired(path, request.url);
      return new Response(JSON.stringify(requirements), {
        status: 402,
        headers: {
          ...CORS_HEADERS,
          'Content-Type': 'application/json',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }

    // Verify payment
    const requirements = buildPaymentRequired(path, request.url);
    const verification = await verifyPayment(paymentHeader, requirements);

    if (!verification.isValid) {
      return jsonResponse(402, {
        error: 'Payment invalid',
        detail: verification.invalidReason || verification.error || 'Verification failed'
      });
    }

    // Process request
    try {
      let result;
      if (path === '/v1/scan') {
        result = await handleScan(request);
      } else if (path === '/v1/audit') {
        result = await handleAudit(request);
      }

      // Add payment confirmation header
      result.headers.set('X-Payment-Confirmed', 'true');
      return result;
    } catch (e) {
      return jsonResponse(500, { error: 'Internal error', detail: e.message });
    }
  }
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      ...CORS_HEADERS,
      'Content-Type': 'application/json',
    }
  });
}
