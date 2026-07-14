import { describe, expect, it } from 'vitest';

import { parseRdsDsn } from './rds.js';

describe('parseRdsDsn', () => {
  it('extracts the parts of an rds-host dsn', () => {
    expect(parseRdsDsn('postgresql://logto@rds:be-prod-db/logto')).toEqual({
      scheme: 'postgresql://',
      username: 'logto',
      cluster: 'be-prod-db',
      rest: '/logto',
    });
  });

  it('keeps the query string', () => {
    expect(parseRdsDsn('postgres://logto@rds:my-cluster/logto?sslmode=no-verify')).toEqual({
      scheme: 'postgres://',
      username: 'logto',
      cluster: 'my-cluster',
      rest: '/logto?sslmode=no-verify',
    });
  });

  it('ignores regular dsns', () => {
    expect(parseRdsDsn('postgresql://logto:secret@db.example.com:5432/logto')).toBeUndefined();
    expect(parseRdsDsn('postgresql://localhost:5432/logto')).toBeUndefined();
    // A password is not allowed in the IAM form — the token is the password.
    expect(parseRdsDsn('postgresql://logto:secret@rds:my-cluster/logto')).toBeUndefined();
  });
});
