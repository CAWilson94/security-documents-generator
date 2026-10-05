import { createHash } from 'crypto';
import { writeFileSync } from 'fs';
import { log } from '../../utils/logger.ts';
import { getAlertIndex } from '../../utils/index.ts';
import { getEsClient } from '../utils/indices.ts';
import { parseUserHit, type EntityHit } from '../utils/entity_store.ts';
import {
  buildAlertDoc,
  buildAnomalyDoc,
  deterministicUuid,
  hasRealAtTimestamp,
  type SeedEntity,
} from './seed_alert_deltas.ts';

const HOUR_MS = 3_600_000;
const SHARED_ANOMALIES_INDEX = '.ml-anomalies-shared';

type Kind = 'host' | 'user';
type KindsOption = 'both' | 'host' | 'user';
type RiskLevel = 'Unknown' | 'Low' | 'Moderate' | 'High' | 'Critical';

export interface SeedDirectBulkOptions {
  space: string;
  /** Number of entities to create in this run. */
  entities: number;
  /** First entity index; use the previous total to extend a population without overlap. */
  startIndex: number;
  /** 'both' alternates host/user (50/50); 'host' or 'user' makes a single-type population. */
  kinds: KindsOption;
  /** Total alerts (across the six comparison slots), spread over distinct entities. */
  alertsTotal: number;
  /** Total anomaly records (across the six comparison slots), spread over distinct entities. */
  anomaliesTotal: number;
  /** Fractions of entities that are current/previous-period risk movers and newly high/critical. */
  curMoverRate: number;
  prevMoverRate: number;
  curNewlyHighRate: number;
  prevNewlyHighRate: number;
  /** Omit kibana.alert.entity.id so the tile queries take the euid derivation path. */
  omitAlertEntityId: boolean;
  bulkSize: number;
  concurrency: number;
  /** Disable replicas and refresh while loading, then restore. */
  tuneIndices: boolean;
  /** Write the counts this data should produce to this JSON file, for later verification. */
  expectedOut?: string;
}

// Comparison slots (hours ago). 24h current = S1, 24h prev = S2; 7d current = S1..S3, prev = S4;
// 30d current = S1..S5, prev = S6.
const SLOTS: ReadonlyArray<readonly [number, number]> = [
  [0, 24],
  [24, 48],
  [48, 168],
  [168, 336],
  [336, 720],
  [720, 1440],
];

// Risk doc times (hours ago): the current-period boundary docs match seed-risk-score-history;
// the prev-* docs sit just before each previous-period boundary (48h / 336h / 1440h).
const RISK_SLOTS = [
  { slot: 'today', hoursAgo: 0, which: 'today' },
  { slot: 'boundary-24h', hoursAgo: 25, which: 'yesterday' },
  { slot: 'boundary-7d', hoursAgo: 169, which: 'yesterday' },
  { slot: 'boundary-30d', hoursAgo: 721, which: 'yesterday' },
  { slot: 'prev-24h', hoursAgo: 49, which: 'prev' },
  { slot: 'prev-7d', hoursAgo: 337, which: 'prev' },
  { slot: 'prev-30d', hoursAgo: 1441, which: 'prev' },
] as const;

// Real Kibana risk score level boundaries (same as seed_risk_score_history.ts).
const scoreNormToLevel = (score: number): RiskLevel => {
  if (score < 20) return 'Unknown';
  if (score < 40) return 'Low';
  if (score < 70) return 'Moderate';
  if (score < 90) return 'High';
  return 'Critical';
};

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

// Deterministic uniform [0,1) from an integer seed (mulberry32), so runs are reproducible.
const rand = (seed: number): number => {
  let t = (seed + 0x6d2b79f5) | 0;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const clamp = (v: number): number => Math.max(0, Math.min(100, Math.round(v * 100) / 100));
const between = (seed: number, min: number, max: number): number => min + rand(seed) * (max - min);

const kindOf = (index: number, kinds: KindsOption): Kind => {
  if (kinds === 'host') return 'host';
  if (kinds === 'user') return 'user';
  return index % 2 === 0 ? 'host' : 'user';
};

interface Scores {
  yesterday: number;
  today: number;
  prev: number;
}

type Scenario = 'cur_mover' | 'prev_mover' | 'cur_newly' | 'prev_newly' | 'stable';

const scoresFor = (index: number, opts: SeedDirectBulkOptions): Scores & { scenario: Scenario } => {
  const r = rand(index * 7 + 1);
  const a = opts.curMoverRate;
  const b = a + opts.prevMoverRate;
  const c = b + opts.curNewlyHighRate;
  const d = c + opts.prevNewlyHighRate;
  const s = index * 13;
  if (r < a) {
    const yesterday = between(s + 2, 5, 65);
    return {
      scenario: 'cur_mover',
      yesterday,
      today: between(s + 3, 80, 98),
      prev: clamp(yesterday + between(s + 4, -5, 5)),
    };
  }
  if (r < b) {
    const prev = between(s + 2, 5, 65);
    const yesterday = between(s + 3, 80, 98);
    return {
      scenario: 'prev_mover',
      prev,
      yesterday,
      today: clamp(yesterday + between(s + 4, -5, 5)),
    };
  }
  if (r < c) {
    const yesterday = between(s + 2, 5, 65);
    return {
      scenario: 'cur_newly',
      yesterday,
      today: between(s + 3, 72, 98),
      prev: clamp(yesterday + between(s + 4, -5, 5)),
    };
  }
  if (r < d) {
    const prev = between(s + 2, 5, 65);
    const yesterday = between(s + 3, 72, 98);
    return {
      scenario: 'prev_newly',
      prev,
      yesterday,
      today: Math.max(70, clamp(yesterday + between(s + 4, -5, 5))),
    };
  }
  const yesterday = between(s + 2, 5, 95);
  return {
    scenario: 'stable',
    yesterday,
    today: clamp(yesterday + between(s + 3, -5, 5)),
    prev: clamp(yesterday + between(s + 4, -5, 5)),
  };
};

interface BuiltEntity {
  kind: Kind;
  entityId: string;
  doc: Record<string, unknown>;
  seed: SeedEntity;
  scores: Scores & { scenario: Scenario };
}

const buildEntity = (index: number, now: number, opts: SeedDirectBulkOptions): BuiltEntity => {
  const kind = kindOf(index, opts.kinds);
  const scores = scoresFor(index, opts);
  // first_seen spread over the last 90 days so the New entity tile has current and previous hits.
  const firstSeen = new Date(now - between(index * 17 + 5, 0, 90 * 24) * HOUR_MS).toISOString();
  const nowIso = new Date(now).toISOString();
  const risk = {
    calculated_score: scores.today,
    calculated_score_norm: scores.today,
    calculated_level: scoreNormToLevel(scores.today),
  };

  if (kind === 'host') {
    const hostName = `nat-host-${index}`;
    const hostId = `nat-host-id-${index}`;
    const entityId = `host:${hostId}`;
    const doc = {
      '@timestamp': nowIso,
      data_stream: { dataset: 'okta.system' },
      host: { name: hostName, id: hostId },
      event: { module: 'okta', dataset: 'okta.system' },
      entity: {
        lifecycle: { first_seen: firstSeen, last_activity: nowIso, last_seen: nowIso },
        EngineMetadata: { Type: 'host', UntypedId: hostId },
        name: hostName,
        risk,
        source: 'okta',
        id: entityId,
        type: 'Host',
      },
    };
    return {
      kind,
      entityId,
      doc,
      scores,
      seed: { kind: 'host', entityId, host: { id: hostId, name: hostName } },
    };
  }

  const userName = `nat-user-${index}`;
  const email = `${userName}@example.com`;
  const entityId = `user:${email}@okta`;
  const doc = {
    '@timestamp': nowIso,
    data_stream: { dataset: 'okta.system' },
    event: { kind: 'asset', module: 'okta', category: 'iam', type: 'user', dataset: 'okta.system' },
    user: { name: userName, id: `nat-user-id-${index}`, email },
    entity: {
      lifecycle: { first_seen: firstSeen, last_activity: nowIso, last_seen: nowIso },
      EngineMetadata: { Type: 'user', UntypedId: `${email}@okta` },
      confidence: 'high',
      namespace: 'okta',
      name: userName,
      risk,
      source: 'okta',
      id: entityId,
      type: 'Identity',
    },
  };
  const hit: EntityHit = { _id: sha256(entityId), _index: 'direct', _source: doc };
  const user = parseUserHit(hit);
  if (!user) throw new Error(`parseUserHit rejected synthetic user ${entityId}`);
  return { kind, entityId, doc, scores, seed: { kind: 'user', entityId, user } };
};

const buildRiskDocs = (
  e: BuiltEntity,
  now: number,
  space: string,
): Array<{ _id: string; doc: Record<string, unknown> }> =>
  RISK_SLOTS.map(({ slot, hoursAgo, which }) => {
    const score =
      which === 'today'
        ? e.scores.today
        : which === 'yesterday'
          ? e.scores.yesterday
          : e.scores.prev;
    return {
      _id: `seed-direct-${space}-${e.entityId}-${slot}`,
      doc: {
        '@timestamp': new Date(now - hoursAgo * HOUR_MS).toISOString(),
        [e.kind]: {
          name: e.entityId,
          risk: {
            calculated_score: score,
            calculated_score_norm: score,
            calculated_level: scoreNormToLevel(score),
            id_field: 'entity.id',
            id_value: e.entityId,
            score_type: 'base',
          },
        },
      },
    };
  });

type Doc = { _id: string; doc: Record<string, unknown> };

const bulkIndex = async (
  index: string,
  action: 'create' | 'index',
  docs: Doc[],
  opts: Pick<SeedDirectBulkOptions, 'bulkSize' | 'concurrency'>,
): Promise<{ indexed: number; conflicts: number; failed: number }> => {
  const client = getEsClient();
  const counts = { indexed: 0, conflicts: 0, failed: 0 };
  const chunks: Doc[][] = [];
  for (let i = 0; i < docs.length; i += opts.bulkSize)
    chunks.push(docs.slice(i, i + opts.bulkSize));
  let next = 0;
  const worker = async () => {
    while (next < chunks.length) {
      const chunk = chunks[next++];
      const result = await client.bulk({
        refresh: false,
        operations: chunk.flatMap(({ _id, doc }) => [{ [action]: { _index: index, _id } }, doc]),
      });
      for (const item of result.items) {
        const op = item.create ?? item.index;
        if (!op?.error) counts.indexed++;
        else if (op.status === 409) counts.conflicts++;
        else {
          counts.failed++;
          if (counts.failed <= 3) log.error(`Bulk item failed in ${index}`, op.error);
        }
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, opts.concurrency) }, worker));
  return counts;
};

const tune = async (indices: string[], on: boolean, saved: Map<string, string | undefined>) => {
  const client = getEsClient();
  for (const index of indices) {
    try {
      if (on) {
        const current = (await client.indices.getSettings({
          index,
          flat_settings: true,
        })) as Record<string, { settings: Record<string, string> }>;
        saved.set(index, Object.values(current)[0]?.settings['index.number_of_replicas']);
        await client.indices.putSettings({
          index,
          settings: { number_of_replicas: 0, refresh_interval: '-1' },
        });
      } else {
        await client.indices.putSettings({
          index,
          settings: { number_of_replicas: Number(saved.get(index) ?? 1), refresh_interval: '1s' },
        });
        await client.indices.refresh({ index });
      }
    } catch (error) {
      log.warn(`Could not ${on ? 'tune' : 'restore'} ${index}: ${String(error).slice(0, 160)}`);
    }
  }
};

export const seedDirectBulk = async (opts: SeedDirectBulkOptions): Promise<void> => {
  const { space, entities, startIndex } = opts;
  const now = Date.now();
  const latestIndex = '.entities.v2.latest.default-00001'; // resolved below if different
  const alertIndex = getAlertIndex(space);
  const riskIndex = `risk-score.risk-score-${space}`;
  const client = getEsClient();

  // Resolve the write index behind the entities-latest alias for this space.
  const alias = `.entities.v2.latest.security_${space}`;
  let entityIndex = latestIndex;
  try {
    const aliasInfo = await client.indices.getAlias({ name: alias });
    entityIndex = Object.keys(aliasInfo)[0] ?? latestIndex;
  } catch {
    log.warn(`Alias ${alias} not found; falling back to ${latestIndex}`);
  }

  log.info(
    `Direct bulk seed: ${entities} entities from index ${startIndex} (${opts.kinds}), ` +
      `${opts.alertsTotal} alerts, ${opts.anomaliesTotal} anomalies, into ${entityIndex}`,
  );

  const savedSettings = new Map<string, string | undefined>();
  const tunedIndices = [entityIndex, riskIndex, alertIndex, SHARED_ANOMALIES_INDEX];
  if (opts.tuneIndices) await tune(tunedIndices, true, savedSettings);

  const expected = {
    entities: { host: 0, user: 0 },
    curMovers: 0,
    prevMovers: 0,
    curNewlyHighCritical: 0,
    prevNewlyHighCritical: 0,
    riskDocs: 0,
    alerts: 0,
    anomalies: 0,
    alertsBySlot: [] as number[],
    anomaliesBySlot: [] as number[],
  };

  try {
    // Entities + risk docs, in blocks to bound memory.
    const BLOCK = 50_000;
    const started = Date.now();
    const hostIdx: number[] = [];
    const userIdx: number[] = [];
    for (let block = 0; block < entities; block += BLOCK) {
      const count = Math.min(BLOCK, entities - block);
      const entityDocs: Doc[] = [];
      const riskDocs: Doc[] = [];
      for (let i = 0; i < count; i++) {
        const index = startIndex + block + i;
        const e = buildEntity(index, now, opts);
        entityDocs.push({ _id: sha256(e.entityId), doc: e.doc });
        riskDocs.push(...buildRiskDocs(e, now, space));
        (e.kind === 'host' ? hostIdx : userIdx).push(index);
        expected.entities[e.kind]++;
        if (e.scores.today - e.scores.yesterday >= 10) expected.curMovers++;
        if (e.scores.yesterday - e.scores.prev >= 10) expected.prevMovers++;
        if (e.scores.today >= 70 && e.scores.yesterday < 70) expected.curNewlyHighCritical++;
        if (e.scores.yesterday >= 70 && e.scores.prev < 70) expected.prevNewlyHighCritical++;
      }
      const a = await bulkIndex(entityIndex, 'index', entityDocs, opts);
      const b = await bulkIndex(riskIndex, 'create', riskDocs, opts);
      expected.riskDocs += riskDocs.length;
      log.info(
        `  block ${block / BLOCK + 1}: entities ${a.indexed} (failed ${a.failed}), risk docs ${b.indexed} ` +
          `(conflicts ${b.conflicts}, failed ${b.failed}) — ${((block + count) / ((Date.now() - started) / 1000)) | 0} entities/s overall`,
      );
    }

    // Alerts and anomalies: spread over distinct entities, alternating host/user, six slots.
    const kindsAvailable: Kind[] = opts.kinds === 'both' ? ['host', 'user'] : [opts.kinds];
    const pools: Record<Kind, number[]> = { host: hostIdx, user: userIdx };
    const stride = (n: number) => (n % 7919 === 0 ? 7907 : 7919);
    const pickEntity = (j: number): number => {
      const kind = kindsAvailable[j % kindsAvailable.length];
      const pool = pools[kind];
      return pool[(Math.floor(j / kindsAvailable.length) * stride(pool.length)) % pool.length];
    };
    const slotOf = (j: number) => j % SLOTS.length;
    const tsIn = (slot: number, seed: number) => {
      const [fromH, toH] = SLOTS[slot];
      return Math.floor(now - (fromH + rand(seed) * (toH - fromH)) * HOUR_MS);
    };

    const alertDocs: Doc[] = [];
    expected.alertsBySlot = SLOTS.map(() => 0);
    for (let j = 0; j < opts.alertsTotal; j++) {
      const index = pickEntity(j);
      const e = buildEntity(index, now, opts);
      const slot = slotOf(j);
      const _id = `seed-direct-alert-${space}-${e.entityId}-${j}`;
      alertDocs.push({
        _id,
        doc: buildAlertDoc(
          e.seed,
          space,
          tsIn(slot, j * 31 + 7),
          deterministicUuid(_id),
          opts.omitAlertEntityId,
        ),
      });
      expected.alertsBySlot[slot]++;
    }
    const alertCounts = await bulkIndex(alertIndex, 'create', alertDocs, opts);
    expected.alerts = alertDocs.length;

    const writeAtTimestamp = await hasRealAtTimestamp(SHARED_ANOMALIES_INDEX);
    const anomalyDocs: Doc[] = [];
    expected.anomaliesBySlot = SLOTS.map(() => 0);
    for (let j = 0; j < opts.anomaliesTotal; j++) {
      const index = pickEntity(j + 1_000_003);
      const e = buildEntity(index, now, opts);
      const slot = slotOf(j);
      const doc = buildAnomalyDoc(e.seed, tsIn(slot, j * 53 + 11), slot, writeAtTimestamp);
      if (!doc) continue;
      anomalyDocs.push({ _id: `seed-direct-anom-${space}-${e.entityId}-${j}`, doc });
      expected.anomaliesBySlot[slot]++;
    }
    const anomalyCounts = await bulkIndex(SHARED_ANOMALIES_INDEX, 'create', anomalyDocs, opts);
    expected.anomalies = anomalyDocs.length;
    log.info(
      `Alerts indexed ${alertCounts.indexed} (failed ${alertCounts.failed}); anomalies indexed ${anomalyCounts.indexed} (failed ${anomalyCounts.failed}).`,
    );
  } finally {
    if (opts.tuneIndices) await tune(tunedIndices, false, savedSettings);
  }

  log.info(`Expected: ${JSON.stringify(expected)}`);
  if (opts.expectedOut) writeFileSync(opts.expectedOut, JSON.stringify(expected, null, 2));
  log.info('Direct bulk seed complete.');
};
