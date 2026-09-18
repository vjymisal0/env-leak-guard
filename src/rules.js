export const SECRET_RULES = [
  {
    id: 'openai-api-key',
    name: 'OpenAI Secret Key',
    category: 'api_key',
    severity: 'critical',
    regex: /(?:sk-[a-zA-Z0-9_-]{20,}T3BlbkFJ[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{48,}|sk-[a-zA-Z0-9]{32,48})/g,
    mask: (m) => m.slice(0, 7) + '...' + m.slice(-4)
  },
  {
    id: 'anthropic-api-key',
    name: 'Anthropic Claude API Key',
    category: 'api_key',
    severity: 'critical',
    regex: /sk-ant-(?:api[0-9]{2}|admin[0-9]{2})-[a-zA-Z0-9_-]{80,110}/g,
    mask: (m) => m.slice(0, 11) + '...' + m.slice(-4)
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    category: 'token',
    severity: 'high',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    mask: (m) => m.slice(0, 4) + '...' + m.slice(-4)
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key Assignment',
    category: 'token',
    severity: 'critical',
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?/gi,
    mask: (m) => m.slice(0, 10) + '...'
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret API Key',
    category: 'api_key',
    severity: 'critical',
    regex: /(?:sk_live|rk_live)_[0-9a-zA-Z]{24,34}/g,
    mask: (m) => m.slice(0, 8) + '...' + m.slice(-4)
  },
  {
    id: 'github-pat',
    name: 'GitHub Personal Access Token',
    category: 'token',
    severity: 'critical',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}/g,
    mask: (m) => m.slice(0, 6) + '...' + m.slice(-4)
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    category: 'token',
    severity: 'high',
    regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    mask: (m) => m.slice(0, 8) + '...'
  },
  {
    id: 'private-key',
    name: 'Private RSA/EC/OpenSSH Key',
    category: 'private_key',
    severity: 'critical',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    mask: () => '-----BEGIN PRIVATE KEY----- [REDACTED]'
  },
  {
    id: 'jwt-secret-payload',
    name: 'Exposed JWT Token',
    category: 'token',
    severity: 'medium',
    regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    mask: (m) => m.slice(0, 12) + '...[JWT]...' + m.slice(-6)
  },
  {
    id: 'database-connection-uri',
    name: 'Database URI with Embedded Credentials',
    category: 'database_uri',
    severity: 'critical',
    regex: /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp):\/\/[^:\s'"]+:([^@\s'"]+)@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[^\s'"]*/gi,
    mask: (m) => m.replace(/:([^@\s'"]+)@/, ':****@')
  }
];
