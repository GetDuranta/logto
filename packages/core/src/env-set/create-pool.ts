import { createPoolWithRetry } from '@logto/cli/lib/pool-retry.js';
import { resolveRdsDsn } from '@logto/shared';
import { assert, conditional } from '@silverhand/essentials';
import {
  createMockPool,
  createMockQueryResult,
  createPool,
  parseDsn,
  createInterceptorsPreset,
} from '@silverhand/slonik';

const createPoolByEnv = async (
  databaseDsn: string,
  mockDatabaseConnection: boolean,
  poolSize?: number,
  connectionTimeout?: number,
  statementTimeout?: number | 'DISABLE_TIMEOUT'
) => {
  // Database connection is disabled in unit test environment
  if (mockDatabaseConnection) {
    return createMockPool({ query: async () => createMockQueryResult([]) });
  }

  // `rds:`-host DSNs select RDS IAM authentication; regular DSNs pass through.
  const { dsn, PgPool } = await resolveRdsDsn(databaseDsn);

  assert(parseDsn(dsn).databaseName, new Error('Database name is required'));

  const poolOptions = {
    interceptors: createInterceptorsPreset(),
    maximumPoolSize: poolSize,
    connectionTimeout,
    ...conditional(statementTimeout !== undefined && { statementTimeout }),
    ...conditional(PgPool && { PgPool }),
  };

  return createPoolWithRetry(async () => createPool(dsn, poolOptions));
};

export default createPoolByEnv;
