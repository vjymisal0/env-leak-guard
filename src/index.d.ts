export interface SecretFinding {
  ruleId: string;
  ruleName: string;
  category: string;
  severity: 'critical' | 'high' | 'medium';
  file: string;
  line: number;
  column: number;
  maskedMatch: string;
  preview: string;
}

export interface ScanOptions {
  ignoreFiles?: string[];
  maxFileSize?: number;
  customRules?: any[];
}

export declare const SECRET_RULES: any[];

export declare function scanContent(
  content: string,
  filePath?: string,
  customRules?: any[]
): SecretFinding[];

export declare function scanPath(
  targetPath: string,
  options?: ScanOptions
): Promise<SecretFinding[]>;
