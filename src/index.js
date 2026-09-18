import fs from 'node:fs';
import path from 'node:path';
import { SECRET_RULES } from './rules.js';
const DEFAULT_IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'coverage',
  '.turbo',
  '.next/cache'
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.svgz',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar',
  '.exe', '.dll', '.dylib', '.so', '.wasm'
]);

/**
 * Scans a string content for exposed secrets.
 */
export function scanContent(content, filePath = 'inline', customRules = SECRET_RULES) {
  const findings = [];
  const lines = content.split(/\r?\n/);

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const lineText = lines[lineIdx];

    for (const rule of customRules) {
      rule.regex.lastIndex = 0;
      let match;
      while ((match = rule.regex.exec(lineText)) !== null) {
        const fullMatch = match[0];
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          severity: rule.severity,
          file: filePath,
          line: lineIdx + 1,
          column: match.index + 1,
          maskedMatch: rule.mask(fullMatch),
          preview: lineText.trim()
        });
      }
    }
  }

  return findings;
}

/**
 * Recursively scans files in a directory or a single file.
 */
export async function scanPath(targetPath, options = {}) {
  const maxBytes = options.maxFileSize ?? 2 * 1024 * 1024; // 2MB
  const rules = options.customRules ?? SECRET_RULES;
  const ignorePatterns = options.ignoreFiles ?? [];

  const findings = [];

  async function walk(current) {
    let stat;
    try {
      stat = await fs.promises.stat(current);
    } catch {
      return;
    }

    if (stat.isDirectory()) {
      const base = path.basename(current);
      if (DEFAULT_IGNORED_DIRS.has(base)) return;

      const entries = await fs.promises.readdir(current);
      for (const entry of entries) {
        await walk(path.join(current, entry));
      }
    } else if (stat.isFile()) {
      if (stat.size > maxBytes) return;

      const ext = path.extname(current).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) return;

      if (ignorePatterns.some((pattern) => current.includes(pattern))) {
        return;
      }

      try {
        const content = await fs.promises.readFile(current, 'utf8');
        const fileFindings = scanContent(content, current, rules);
        findings.push(...fileFindings);
      } catch {
        // Skip unreadable files
      }
    }
  }

  await walk(path.resolve(targetPath));
  return findings;
}

export { SECRET_RULES };
