import { DescribeDBClustersCommand, RDSClient } from '@aws-sdk/client-rds';
import { Signer } from '@aws-sdk/rds-signer';
import pg from 'pg';

import { rdsCaBundle } from './rds-ca.js';

/**
 * RDS IAM authentication, following the same DSN convention as the Duranta Go
 * backend: a DSN whose host is `rds:<cluster-name>` — e.g.
 * `postgresql://logto@rds:be-prod-db/logto` — selects IAM authentication. The
 * cluster name is resolved to its endpoint through the RDS API, connections
 * are TLS-encrypted against the bundled AWS RDS CA set, and every connection
 * presents a freshly minted IAM auth token instead of a password.
 *
 * The task role needs `rds:DescribeDBClusters` and `rds-db:connect`, and the
 * database user must be granted the `rds_iam` role.
 */

const rdsDsnPattern =
  /^(?<scheme>postgres(?:ql)?:\/\/)(?<username>[^/:@]+)@rds:(?<cluster>[^/?]+)(?<rest>[/?].*)?$/;

export type RdsDsnParts = {
  scheme: string;
  username: string;
  cluster: string;
  /** Path and query of the DSN (e.g. `/logto?sslmode=no-verify`). */
  rest: string;
};

/** Extracts the parts of an `rds:`-host DSN; undefined for regular DSNs. */
export const parseRdsDsn = (dsn: string): RdsDsnParts | undefined => {
  const groups = rdsDsnPattern.exec(dsn)?.groups;

  if (!groups?.scheme || !groups.username || !groups.cluster) {
    return undefined;
  }

  return {
    scheme: groups.scheme,
    username: groups.username,
    cluster: groups.cluster,
    rest: groups.rest ?? '',
  };
};

export type ResolvedDsn = {
  dsn: string;
  /**
   * A `pg.Pool` subclass that mints an IAM auth token per connection; pass as
   * the `PgPool` override of slonik's client configuration. Undefined for
   * regular (non-`rds:`) DSNs.
   */
  PgPool?: new (config?: pg.PoolConfig) => pg.Pool;
};

const resolvedDsns = new Map<string, Promise<ResolvedDsn>>();

/**
 * Resolves an `rds:`-host DSN into a connectable DSN plus the IAM-token pool
 * class; regular DSNs pass through unchanged. Resolutions are memoized per
 * DSN (failures are not, so pool-creation retries re-resolve).
 */
export const resolveRdsDsn = async (dsn: string): Promise<ResolvedDsn> => {
  const parts = parseRdsDsn(dsn);

  if (!parts) {
    return { dsn };
  }

  const cached = resolvedDsns.get(dsn);

  if (cached) {
    return cached;
  }

  const pending = (async () => {
    try {
      return await resolveCluster(parts);
    } catch (error) {
      resolvedDsns.delete(dsn);
      throw error;
    }
  })();
  resolvedDsns.set(dsn, pending);

  return pending;
};

const resolveCluster = async ({
  scheme,
  username,
  cluster,
  rest,
}: RdsDsnParts): Promise<ResolvedDsn> => {
  const client = new RDSClient();
  const { DBClusters } = await client.send(
    new DescribeDBClustersCommand({ DBClusterIdentifier: cluster, IncludeShared: true })
  );

  const endpoint = DBClusters?.[0]?.Endpoint;
  const port = DBClusters?.[0]?.Port ?? 5432;

  if (!endpoint) {
    throw new Error(`Cannot resolve the RDS cluster "${cluster}"`);
  }

  const region = await client.config.region();
  const signer = new Signer({ hostname: endpoint, port, username, region });

  class RdsIamPool extends pg.Pool {
    constructor(config?: pg.PoolConfig) {
      super({
        ...config,
        password: async () => signer.getAuthToken(),
        ssl: { ca: rdsCaBundle, servername: endpoint, rejectUnauthorized: true },
      });
    }
  }

  return {
    dsn: `${scheme}${username}@${endpoint}:${port}${rest}`,
    PgPool: RdsIamPool,
  };
};
