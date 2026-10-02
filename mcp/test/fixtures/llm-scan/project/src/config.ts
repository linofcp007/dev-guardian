// Test fixture. The key below is AWS's own documentation example, not a
// credential; it is here so the brief's secret redaction has something to
// redact.

export const AWS_REGION = 'eu-west-1';
export const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';

export const SESSION_SECRET = process.env.SESSION_SECRET ?? 'dev-only-session';

export function bucketUrl(bucket: string): string {
  return `https://${bucket}.s3.${AWS_REGION}.amazonaws.com`;
}
