import test from 'node:test';
import assert from 'node:assert/strict';
import { scanContent } from '../src/index.js';

test('detects exposed OpenAI API key', () => {
  const content = 'const key = "sk-proj-abcdef1234567890abcdef1234567890abcdef1234567890abcdef";';
  const findings = scanContent(content);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'openai-api-key');
  assert.equal(findings[0].severity, 'critical');
  assert.ok(findings[0].maskedMatch.includes('...'));
});

test('detects exposed AWS access key ID', () => {
  const content = 'export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE";';
  const findings = scanContent(content);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'aws-access-key');
  assert.equal(findings[0].severity, 'high');
});

test('detects database connection string with password', () => {
  const content = 'DATABASE_URL="postgres://admin:supersecretpassword123@db.internal.net:5432/production"';
  const findings = scanContent(content);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'database-connection-uri');
  assert.ok(findings[0].maskedMatch.includes(':****@'));
});

test('returns empty array when content is clean', () => {
  const cleanCode = `
    import express from 'express';
    const app = express();
    const port = process.env.PORT || 3000;
    app.listen(port);
  `;
  const findings = scanContent(cleanCode);
  assert.equal(findings.length, 0);
});
