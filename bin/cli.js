#!/usr/bin/env node
import path from 'node:path';
import { scanPath } from '../src/index.js';

const args = process.argv.slice(2);
const target = args[0] || '.';

console.log(`🔍 Scanning for exposed secrets in: ${path.resolve(target)}`);

scanPath(target)
  .then((findings) => {
    if (findings.length === 0) {
      console.log('✅ No exposed secrets detected! Clean scan.');
      process.exit(0);
    }

    console.error(`\n🚨 FOUND ${findings.length} POTENTIAL SECRET LEAK(S):\n`);
    for (const f of findings) {
      const severityTag =
        f.severity === 'critical' ? '🔴 [CRITICAL]' : f.severity === 'high' ? '🟠 [HIGH]' : '🟡 [WARN]';

      console.error(`${severityTag} ${f.ruleName}`);
      console.error(`  Location: ${f.file}:${f.line}:${f.column}`);
      console.error(`  Secret:   ${f.maskedMatch}`);
      console.error(`  Snippet:  ${f.preview.slice(0, 100)}...\n`);
    }

    process.exit(1);
  })
  .catch((err) => {
    console.error('Scan error:', err);
    process.exit(2);
  });
