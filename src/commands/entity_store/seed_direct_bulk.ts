import { createHash } from 'crypto';
import { writeFileSync } from 'fs';
import { log } from '../../utils/logger.ts';
import { getAlertIndex } from '../../utils/index.ts';
import { createWatchlist } from '../../utils/kibana_api.ts';
import { getEsClient } from '../utils/indices.ts';
import { parseUserHit, type EntityHit } from '../utils/entity_store.ts';
import {
  buildAlertDoc,
  buildAnomalyDoc,
  deterministicUuid,
  hasRealAtTimestamp,
  type SeedEntity,
} from './seed_alert_deltas.ts';
import {
  HOUR_MS,
  RISK_GRID_HOURS,
  addRiskSeriesCounts,
  between,
  clamp,
  createEventSeries,
  createRiskSeriesCounts,
  rand,
  riskWalk,
  scoreNormToLevel,
  summarizeRiskSeries,
} from './seed_series.ts';

const SHARED_ANOMALIES_INDEX = '.ml-anomalies-shared';

type Kind = 'host' | 'user';
type KindsOption = 'both' | 'host' | 'user';
type RiskHistoryOption = 'boundaries' | 'series';
type AlertProfileOption = 'slots' | 'uniform';

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
  /**
   * 'boundaries' writes the 7 fixed risk docs per entity. 'series' writes risk docs on the
   * sparkline bucket grid (about 143 per entity) from each entity's first_seen, with scores
   * that vary per point. In 'series' the mover and newly-high rates only shape each entity's
   * score today (a 'mover' scenario gets a high score today); how many entities count as
   * movers at a given point comes from the score walk, so those counts are emergent.
   */
  riskHistory: RiskHistoryOption;
  /** 'slots' spreads alerts over six windows of unequal length; 'uniform' spreads them evenly. */
  alertProfile: AlertProfileOption;
  /** Only used by the 'uniform' profile: alerts and anomalies land in the last N hours. */
  alertHorizonHours: number;
  /** Fraction of entities (per kind) that can receive alerts and anomalies; below 1 makes them repeat. */
  alertEntityFraction: number;
  /** Fraction of the alert-eligible entities that carry a watchlist. Needs a running Kibana. */
  watchlistedRate: number;
  /** Write the expected per-bucket series (alerts, anomalies, new entity, risk) to this file. */
  expectedSeriesOut?: string;
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

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

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
  /** Hours between first_seen and now. */
  ageHours: number;
}

const buildEntity = (
  index: number,
  now: number,
  opts: SeedDirectBulkOptions,
  watchlistIds: readonly string[] = [],
): BuiltEntity => {
  const kind = kindOf(index, opts.kinds);
  const scores = scoresFor(index, opts);
  // first_seen spread over the last 90 days so the New entity tile has current and previous hits.
  const ageHours = between(index * 17 + 5, 0, 90 * 24);
  const firstSeen = new Date(now - ageHours * HOUR_MS).toISOString();
  const attributes =
    watchlistIds.length > 0 ? { attributes: { watchlists: [...watchlistIds] } } : {};
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
        ...attributes,
      },
    };
    return {
      kind,
      entityId,
      doc,
      scores,
      ageHours,
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
      ...attributes,
    },
  };
  const hit: EntityHit = { _id: sha256(entityId), _index: 'direct', _source: doc };
  const user = parseUserHit(hit);
  if (!user) throw new Error(`parseUserHit rejected synthetic user ${entityId}`);
  return { kind, entityId, doc, scores, ageHours, seed: { kind: 'user', entityId, user } };
};

type Doc = { _id: string; doc: Record<string, unknown> };

const buildRiskDoc = (e: BuiltEntity, id: string, timestampMs: number, score: number): Doc => ({
  _id: id,
  doc: {
    '@timestamp': new Date(timestampMs).toISOString(),
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
});

const buildRiskDocs = (e: BuiltEntity, now: number, space: string): Doc[] =>
  RISK_SLOTS.map(({ slot, hoursAgo, which }) => {
    const score =
      which === 'today'
        ? e.scores.today
        : which === 'yesterday'
          ? e.scores.yesterday
          : e.scores.prev;
    return buildRiskDoc(
      e,
      `seed-direct-${space}-${e.entityId}-${slot}`,
      now - hoursAgo * HOUR_MS,
      score,
    );
  });

// One doc per risk grid time from today back to the entity's first_seen.
const buildSeriesRiskDocs = (
  e: BuiltEntity,
  scores: Float64Array,
  now: number,
  space: string,
): Doc[] => {
  const docs: Doc[] = [];
  RISK_GRID_HOURS.forEach((hoursAgo, i) => {
    if (Number.isNaN(scores[i])) return;
    docs.push(
      buildRiskDoc(
        e,
        `seed-direct-${space}-${e.entityId}-h${hoursAgo}`,
        now - hoursAgo * HOUR_MS,
        scores[i],
      ),
    );
  });
  return docs;
};

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
      `${opts.alertsTotal} alerts, ${opts.anomaliesTotal} anomalies, into ${entityIndex} ` +
      `(risk history: ${opts.riskHistory}, alert profile: ${opts.alertProfile})`,
  );

  const seriesRisk = opts.riskHistory === 'series';
  const wantSeries = Boolean(opts.expectedSeriesOut);
  const kindsAvailable: Kind[] = opts.kinds === 'both' ? ['host', 'user'] : [opts.kinds];

  // Alerts and anomalies go to the first `poolSize(kind)` entities of each kind, so a fraction
  // below 1 makes them repeat. Watchlists are only stamped on entities inside that pool.
  const poolFraction = Math.min(1, Math.max(0, opts.alertEntityFraction));
  const kindTotals: Record<Kind, number> = { host: 0, user: 0 };
  for (let i = 0; i < entities; i++) kindTotals[kindOf(startIndex + i, opts.kinds)]++;
  const poolSize = (kind: Kind): number =>
    kindTotals[kind] === 0 ? 0 : Math.max(1, Math.floor(kindTotals[kind] * poolFraction));
  const isWatchlisted = (index: number): boolean =>
    opts.watchlistedRate > 0 && rand(index * 19 + 3) < opts.watchlistedRate;

  const watchlistIds: string[] = [];
  if (opts.watchlistedRate > 0) {
    const watchlist = await createWatchlist({
      name: `nat-perf-watchlist-${now}`,
      riskModifier: 1.5,
      space,
    });
    watchlistIds.push(watchlist.id);
    log.info(`Created watchlist ${watchlist.name} (${watchlist.id})`);
  }

  const savedSettings = new Map<string, string | undefined>();
  const tunedIndices = [entityIndex, riskIndex, alertIndex, SHARED_ANOMALIES_INDEX];
  if (opts.tuneIndices) await tune(tunedIndices, true, savedSettings);

  const riskCounts = wantSeries && seriesRisk ? createRiskSeriesCounts() : undefined;
  const alertSeries = wantSeries ? createEventSeries(now) : undefined;
  const watchlistedSeries = wantSeries ? createEventSeries(now) : undefined;
  const anomalySeries = wantSeries ? createEventSeries(now) : undefined;
  const newEntitySeries = wantSeries ? createEventSeries(now) : undefined;

  // The mover and newly-high counts below only describe 'boundaries' history; for 'series' see
  // the --expected-series-out file.
  const expected = {
    riskHistory: opts.riskHistory,
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
    // Entities + risk docs, in blocks to bound memory (series history is ~20x more risk docs).
    const BLOCK = seriesRisk ? Math.max(200, Math.floor(300_000 / RISK_GRID_HOURS.length)) : 50_000;
    const started = Date.now();
    const hostIdx: number[] = [];
    const userIdx: number[] = [];
    const positions: Record<Kind, number> = { host: 0, user: 0 };
    for (let block = 0; block < entities; block += BLOCK) {
      const count = Math.min(BLOCK, entities - block);
      const entityDocs: Doc[] = [];
      const riskDocs: Doc[] = [];
      for (let i = 0; i < count; i++) {
        const index = startIndex + block + i;
        const kind = kindOf(index, opts.kinds);
        const watched = isWatchlisted(index) && positions[kind] < poolSize(kind);
        positions[kind]++;
        const e = buildEntity(index, now, opts, watched ? watchlistIds : []);
        entityDocs.push({ _id: sha256(e.entityId), doc: e.doc });
        (e.kind === 'host' ? hostIdx : userIdx).push(index);
        expected.entities[e.kind]++;
        if (e.scores.today > 0) {
          newEntitySeries?.add(Math.trunc(now - e.ageHours * HOUR_MS), index);
        }
        if (seriesRisk) {
          const scores = riskWalk(index, e.scores.today, e.ageHours);
          riskDocs.push(...buildSeriesRiskDocs(e, scores, now, space));
          if (riskCounts) addRiskSeriesCounts(riskCounts, scores);
          continue;
        }
        riskDocs.push(...buildRiskDocs(e, now, space));
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

    // Alerts and anomalies: alternating host/user, spread over the alert-eligible entities.
    const pools: Record<Kind, number[]> = { host: hostIdx, user: userIdx };
    const stride = (n: number) => (n % 7919 === 0 ? 7907 : 7919);
    const pickEntity = (j: number): number => {
      const kind = kindsAvailable[j % kindsAvailable.length];
      const pool = pools[kind];
      const size = Math.min(pool.length, poolSize(kind));
      return pool[(Math.floor(j / kindsAvailable.length) * stride(size)) % size];
    };
    // The slot must not share a period with the kind (j % kinds), or each slot would only ever get one kind.
    const slotOf = (j: number) => Math.floor(j / kindsAvailable.length) % SLOTS.length;
    const slotOfTimestamp = (timestampMs: number) => {
      const hoursAgo = (now - timestampMs) / HOUR_MS;
      const slot = SLOTS.findIndex(([fromH, toH]) => hoursAgo >= fromH && hoursAgo < toH);
      return slot === -1 ? SLOTS.length - 1 : slot;
    };
    // 'slots': equal counts per slot, so a short slot is denser. 'uniform': an even rate over time.
    const eventTime = (j: number, seed: number): { slot: number; timestamp: number } => {
      if (opts.alertProfile === 'uniform') {
        const timestamp = Math.floor(now - rand(seed) * opts.alertHorizonHours * HOUR_MS);
        return { slot: slotOfTimestamp(timestamp), timestamp };
      }
      const slot = slotOf(j);
      const [fromH, toH] = SLOTS[slot];
      return { slot, timestamp: Math.floor(now - (fromH + rand(seed) * (toH - fromH)) * HOUR_MS) };
    };

    const alertDocs: Doc[] = [];
    expected.alertsBySlot = SLOTS.map(() => 0);
    for (let j = 0; j < opts.alertsTotal; j++) {
      const index = pickEntity(j);
      const e = buildEntity(index, now, opts);
      const { slot, timestamp } = eventTime(j, j * 31 + 7);
      const _id = `seed-direct-alert-${space}-${e.entityId}-${j}`;
      alertDocs.push({
        _id,
        doc: buildAlertDoc(
          e.seed,
          space,
          timestamp,
          deterministicUuid(_id),
          opts.omitAlertEntityId,
        ),
      });
      expected.alertsBySlot[slot]++;
      alertSeries?.add(timestamp, index);
      if (isWatchlisted(index)) watchlistedSeries?.add(timestamp, index);
    }
    const alertCounts = await bulkIndex(alertIndex, 'create', alertDocs, opts);
    expected.alerts = alertDocs.length;

    const writeAtTimestamp = await hasRealAtTimestamp(SHARED_ANOMALIES_INDEX);
    const anomalyDocs: Doc[] = [];
    expected.anomaliesBySlot = SLOTS.map(() => 0);
    for (let j = 0; j < opts.anomaliesTotal; j++) {
      const index = pickEntity(j + 1_000_003);
      const e = buildEntity(index, now, opts);
      const { slot, timestamp } = eventTime(j, j * 53 + 11);
      const doc = buildAnomalyDoc(e.seed, timestamp, slot, writeAtTimestamp);
      if (!doc) continue;
      anomalyDocs.push({ _id: `seed-direct-anom-${space}-${e.entityId}-${j}`, doc });
      expected.anomaliesBySlot[slot]++;
      anomalySeries?.add(timestamp, index);
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
  if (
    opts.expectedSeriesOut &&
    alertSeries &&
    watchlistedSeries &&
    anomalySeries &&
    newEntitySeries
  ) {
    // Event buckets are UTC-aligned like ES|QL BUCKET and cover [windowFrom, seededAt]; check
    // them with those fixed bounds, because NOW() in a later query shifts the first bucket.
    const series = {
      seededAt: new Date(now).toISOString(),
      entityCount: entities,
      startIndex,
      riskHistory: opts.riskHistory,
      alertProfile: opts.alertProfile,
      entitiesWithAlerts: alertSeries.summarize(),
      watchlisted: watchlistedSeries.summarize(),
      anomalies: anomalySeries.summarize(),
      newEntity: newEntitySeries.summarize(),
      ...(riskCounts && { risk: summarizeRiskSeries(riskCounts, now) }),
    };
    writeFileSync(opts.expectedSeriesOut, JSON.stringify(series, null, 2));
    log.info(`Expected series written to ${opts.expectedSeriesOut}`);
  }
  log.info('Direct bulk seed complete.');
};
