import {
  adminTenantId,
  LogtoConfigs,
  LogtoOidcConfigKey,
  type OidcPrivateKey,
  oidcPrivateKeyGuard,
} from '@logto/schemas';
import { Tenants } from '@logto/schemas/models';
import { parseRdsDsn } from '@logto/shared';
import { conditional } from '@silverhand/essentials';
import { parseDsn, sql, stringifyDsn } from '@silverhand/slonik';
import { z } from 'zod';

import { EnvSet } from '#src/env-set/index.js';
import { convertToIdentifiers } from '#src/utils/sql.js';

export class TenantNotFoundError extends Error {
  name = 'TenantNotFoundError';
}

const { table: logtoConfigsTable, fields: logtoConfigFields } = convertToIdentifiers(LogtoConfigs);

/**
 * This function is to fetch the tenant password for the corresponding Postgres user.
 *
 * ** **CAUTION** ** In multi-tenancy mode, Logto should ALWAYS use a restricted user with RLS enforced to ensure data isolation between tenants.
 */
export const getTenantDatabaseDsn = async (tenantId: string) => {
  const { sharedPool, dbUrl } = EnvSet;
  const {
    tableName,
    rawKeys: { id, dbUser, dbUserPassword },
  } = Tenants;

  const identifier = (id: string) => sql.identifier([id]);
  const pool = await sharedPool;

  const { rows } = await pool.query(sql`
    select ${identifier(dbUser)}, ${identifier(dbUserPassword)}
    from ${identifier(tableName)}
    where ${identifier(id)} = ${tenantId}
  `);

  if (!rows[0]) {
    throw new TenantNotFoundError(`Cannot find valid tenant credentials for ID ${tenantId}`);
  }

  const { dbUser: username, dbUserPassword: password } = z
    .object({ dbUser: z.string(), dbUserPassword: z.string().optional() })
    .parse(rows[0]);

  // Under RDS IAM (an `rds:`-host dbUrl) the tenant roles authenticate with
  // IAM tokens as well: keep the `rds:` form so that pool creation resolves it
  // and injects a token signer for the tenant user. The stored password is
  // unusable for these roles (`rds_iam` membership disables password auth).
  const rdsParts = parseRdsDsn(dbUrl);
  if (rdsParts) {
    return `${rdsParts.scheme}${username}@rds:${rdsParts.cluster}${rdsParts.rest}`;
  }

  const options = parseDsn(dbUrl);

  return stringifyDsn({
    ...options,
    username,
    password: conditional(typeof password === 'string' && password),
  });
};

/**
 * Read admin tenant signing keys through the shared pool for OSS admin token validation.
 *
 * Like `getTenantDatabaseDsn`, this cannot use tenant-scoped Queries because callers may need
 * admin tenant keys while running in a user tenant whose pool is scoped by RLS.
 */
export const getAdminTenantPrivateSigningKeys = async (): Promise<OidcPrivateKey[]> => {
  const pool = await EnvSet.sharedPool;
  const { value } = await pool.one<{ value: unknown }>(sql`
    select ${logtoConfigFields.value} from ${logtoConfigsTable}
      where ${logtoConfigFields.tenantId} = ${adminTenantId}
      and ${logtoConfigFields.key} = ${LogtoOidcConfigKey.PrivateKeys}
  `);

  return oidcPrivateKeyGuard.array().parse(value);
};
