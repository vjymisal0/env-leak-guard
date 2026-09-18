# env-leak-guard

> Blazing fast zero-dependency scanner to detect leaked API keys, credentials, tokens, and database secrets in source code, build outputs (`dist/`, `.next/`), and git staging.

[![npm version](https://img.shields.io/npm/v/env-leak-guard.svg)](https://www.npmjs.com/package/env-leak-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Why env-leak-guard?

Traditional secret scanners (like Gitleaks or TruffleHog) require heavy external binaries or Docker containers. `env-leak-guard` is:
- **Zero dependencies** (< 15KB total footprint).
- **Fast**: Scans entire directories and build bundles in milliseconds.
- **Pre-commit and CI/CD friendly**: Exits with non-zero code on leak detection.
- **Safe output**: All detected tokens and passwords are automatically masked before logging.

## Detects Out of the Box:
- **OpenAI API keys** (`sk-proj-...`, `sk-...`)
- **Anthropic Claude API keys** (`sk-ant-...`)
- **AWS Access Keys & Secret Keys** (`AKIA...`)
- **Stripe Secret Keys** (`sk_live_...`, `rk_live_...`)
- **GitHub Personal Access Tokens** (`ghp_...`, `gho_...`)
- **Slack Tokens & Webhooks** (`xoxb-...`)
- **Private Keys** (RSA, EC, OpenSSH)
- **Database Connection URIs** with passwords (`postgres://...`, `mongodb://...`, `mysql://...`)
- **Exposed JWT tokens**

## Installation & CLI Usage

Run directly via `npx`:

```bash
# Scan current repository or directory
npx env-leak-guard .

# Scan frontend build outputs before deployment
npx env-leak-guard dist/
```

Or install globally:

```bash
npm install -g env-leak-guard
env-leak-guard .
```

### Pre-commit Hook Integration (Husky)

Add to `.husky/pre-commit`:

```bash
npx env-leak-guard .
```

## Programmatic API

```javascript
import { scanContent, scanPath } from 'env-leak-guard';

// Scan file or directory
const findings = await scanPath('./build');
console.log(findings);

// Or scan a raw string
const results = scanContent('const token = "sk-proj-xyz123...";');
if (results.length > 0) {
  console.error('Leak found:', results[0].maskedMatch);
}
```

## License

MIT © [vjymisal0](https://github.com/vjymisal0)
