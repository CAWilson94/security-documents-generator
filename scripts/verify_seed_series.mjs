// Checks what `seed-direct-bulk --expected-series-out <file>` wrote against what Elasticsearch holds.
//
//   node scripts/verify_seed_series.mjs <expected-series.json> [config.json] [space]
//
// Run it right after seeding: the tile queries are replayed with NOW() pinned, but seeded risk
// data goes stale after about an hour. Checks (all restricted to this run's entity index range):
//  - alerts, anomalies: distinct entities per UTC bucket, with ES|QL BUCKET (COUNT_DISTINCT is
//    approximate, so 1% is allowed) plus an exact client-side distinct count for alerts
//  - New entity, Watchlisted: per bucket, from the entity and alert docs
//  - Risk movers, Newly high/critical: the shipped tile logic replayed at every sparkline point
import { readFileSync } from 'node:fs';

const [expectedPath, configPath = 'config.json', space = 'default'] = process.argv.slice(2);
if (!expectedPath) {
  console.error(
    'usage: node scripts/verify_seed_series.mjs <expected-series.json> [config.json] [space]',
  );
  process.exit(2);
}
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const expected = JSON.parse(readFileSync(expectedPath, 'utf8'));
const { startIndex, entityCount } = expected;
if (startIndex === undefined || entityCount === undefined) {
  console.error(
    'The expected file has no startIndex/entityCount; re-seed with the current seeder.',
  );
  process.exit(2);
}

const auth = `Basic ${Buffer.from(`${config.elastic.username}:${config.elastic.password}`).toString('base64')}`;
const HOUR_MS = 3_600_000;
const seededAt = Date.parse(expected.seededAt);
const iso = (ms) => new Date(ms).toISOString();
const ALERTS_INDEX = `.alerts-security.alerts-${space}`;
const RISK_INDEX = `risk-score.risk-score-${space}`;
const ENTITIES_INDEX = `.entities.v2.latest.security_${space}`;
const ANOMALIES_INDEX = '.ml-anomalies-shared';
const RANGES = [
  { key: '24h', hours: 24, bucket: '1 hour', bucketHours: 1 },
  { key: '7d', hours: 168, bucket: '6 hours', bucketHours: 6 },
  { key: '30d', hours: 720, bucket: '1 day', bucketHours: 24 },
];

// Seeded names end in the entity index (nat-host-10264, host:nat-host-id-10264,
// user:nat-user-10369@example.com@okta), so the digits identify the entity.
const indexOf = (name) => Number(String(name ?? '').replace(/\D/g, ''));
const inRun = (name) => {
  const index = indexOf(name);
  return index >= startIndex && index < startIndex + entityCount;
};
const inRunEsql = (field) =>
  `| EVAL run_index = TO_LONG(REPLACE(${field}, "[^0-9]", "")) | WHERE run_index >= ${startIndex} AND run_index < ${startIndex + entityCount}`;
const firstString = (...values) => values.flat().find((v) => typeof v === 'string');

const call = async (path, body) => {
  const response = await fetch(config.elastic.node + path, {
    method: 'POST',
    headers: { authorization: auth, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await response.json();
  if (json.error) throw new Error(`${path}: ${JSON.stringify(json.error).slice(0, 400)}`);
  return json;
};
const scrollAll = async (index, body) => {
  let page = await call(`/${index}/_search?scroll=2m`, { ...body, size: 5000 });
  const hits = [];
  while (page.hits.hits.length) {
    hits.push(...page.hits.hits);
    page = await call('/_search/scroll', { scroll: '2m', scroll_id: page._scroll_id });
  }
  return hits;
};
const esql = async (query) => (await call('/_query', { query })).values;

let failures = 0;
const report = (label, ok, detail = '') => {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `  ${detail}` : ''}`);
};

const withinTolerance = (actual, want) => Math.abs(actual - want) <= Math.max(1, 0.01 * want);

const compareBuckets = (label, actualRows, expectedBuckets, approximate = false) => {
  const actual = new Map(actualRows.map(([count, bucket]) => [Date.parse(bucket), count]));
  const want = new Map(expectedBuckets.map((b) => [Date.parse(b.bucketStart), b.entities]));
  const keys = new Set([...actual.keys(), ...want.keys()]);
  const diffs = [...keys].filter((k) =>
    approximate
      ? !withinTolerance(actual.get(k) ?? 0, want.get(k) ?? 0)
      : (actual.get(k) ?? 0) !== (want.get(k) ?? 0),
  );
  report(label, diffs.length === 0, `${want.size} expected buckets, ${diffs.length} differ`);
  if (diffs.length) {
    const sample = diffs
      .slice(0, 3)
      .map((k) => `${iso(k)} es=${actual.get(k) ?? 0} expected=${want.get(k) ?? 0}`);
    console.log('      first diffs:', sample);
  }
};

const bucketRows = (map) => [...map.entries()].map(([start, count]) => [count, iso(start)]);

// 1. Alerts: distinct entities per bucket, with ES|QL BUCKET itself.
for (const r of RANGES) {
  const window = `@timestamp >= "${iso(seededAt - r.hours * HOUR_MS)}" AND @timestamp <= "${iso(seededAt)}"`;
  const base = `FROM ${ALERTS_INDEX} | WHERE ${window} | EVAL e = COALESCE(host.name, user.name) ${inRunEsql('e')}`;
  const rows = await esql(
    `${base} | STATS c = COUNT_DISTINCT(e, 40000) BY b = BUCKET(@timestamp, ${r.bucket}) | KEEP c, b | SORT b`,
  );
  compareBuckets(
    `alerts ${r.key} per ${r.bucket} (ES|QL, approx)`,
    rows,
    expected.entitiesWithAlerts[r.key].buckets,
    true,
  );
}

// 2. Anomalies: distinct entities per bucket (host.name / user.name are arrays in the ML docs).
for (const r of RANGES) {
  const window = `@timestamp >= "${iso(seededAt - r.hours * HOUR_MS)}" AND @timestamp <= "${iso(seededAt)}"`;
  const rows = await esql(
    `FROM ${ANOMALIES_INDEX} | WHERE result_type == "record" AND ${window} ` +
      `| EVAL e = COALESCE(MV_FIRST(host.name), MV_FIRST(user.name)) ${inRunEsql('e')} ` +
      `| STATS c = COUNT_DISTINCT(e, 40000) BY b = BUCKET(@timestamp, ${r.bucket}) | KEEP c, b | SORT b`,
  );
  compareBuckets(
    `anomalies ${r.key} per ${r.bucket} (ES|QL, approx)`,
    rows,
    expected.anomalies[r.key].buckets,
    true,
  );
}

// 3. Entities written, watchlisted share, and the New entity series (first_seen, score > 0).
const entities = (
  await scrollAll(ENTITIES_INDEX, {
    _source: [
      'entity.name',
      'entity.lifecycle.first_seen',
      'entity.risk.calculated_score',
      'entity.attributes.watchlists',
    ],
    query: { match_all: {} },
  })
)
  .map((h) => h._source.entity)
  .filter((e) => inRun(e.name));
const watchlisted = new Set(
  entities.filter((e) => e.attributes?.watchlists?.length).map((e) => e.name),
);
console.log(`INFO  run entities in ES: ${entities.length}, with a watchlist: ${watchlisted.size}`);
report(
  'entities written',
  entities.length === entityCount,
  `es=${entities.length} expected=${entityCount}`,
);

for (const r of RANGES) {
  const width = r.bucketHours * HOUR_MS;
  const from = seededAt - r.hours * HOUR_MS;
  const perBucket = new Map();
  for (const e of entities) {
    const t = Date.parse(e.lifecycle.first_seen);
    if (t < from || t > seededAt || !(e.risk.calculated_score > 0)) continue;
    const start = Math.floor(t / width) * width;
    perBucket.set(start, (perBucket.get(start) ?? 0) + 1);
  }
  compareBuckets(`new entity ${r.key}`, bucketRows(perBucket), expected.newEntity[r.key].buckets);
}

// 4. Alerts, exact and for watchlisted entities, per bucket (client side, from the ES docs).
const alerts = (
  await scrollAll(ALERTS_INDEX, {
    _source: ['@timestamp', 'host.name', 'user.name'],
    query: { match_all: {} },
  })
)
  .map((h) => h._source)
  .map((a) => ({
    name: firstString(a['host.name'], a['user.name'], a.host?.name, a.user?.name),
    timestamp: typeof a['@timestamp'] === 'number' ? a['@timestamp'] : Date.parse(a['@timestamp']),
  }))
  .filter((a) => inRun(a.name));

for (const r of RANGES) {
  const width = r.bucketHours * HOUR_MS;
  const from = seededAt - r.hours * HOUR_MS;
  const inWindow = alerts.filter((a) => a.timestamp >= from && a.timestamp <= seededAt);
  const distinct = new Set(inWindow.map((a) => a.name)).size;
  const want = expected.entitiesWithAlerts[r.key].distinctEntities;
  report(
    `alerts ${r.key} distinct entities (exact)`,
    distinct === want,
    `es=${distinct} expected=${want}`,
  );

  const perBucket = new Map();
  for (const a of inWindow) {
    if (!watchlisted.has(a.name)) continue;
    const start = Math.floor(a.timestamp / width) * width;
    const set = perBucket.get(start) ?? new Set();
    set.add(a.name);
    perBucket.set(start, set);
  }
  compareBuckets(
    `watchlisted ${r.key}`,
    [...perBucket.entries()].map(([start, set]) => [set.size, iso(start)]),
    expected.watchlisted[r.key].buckets,
  );
}

// 5. Risk series: the shipped movers / newly high-critical logic with NOW() pinned to each point.
const riskQuery = (kind, r, hoursAgo) => {
  const now = `TO_DATETIME("${iso(seededAt - hoursAgo * HOUR_MS)}")`;
  const head = [
    `FROM ${RISK_INDEX}`,
    `| WHERE @timestamp >= ${now} - ${r.hours + 2}h AND @timestamp <= ${now}`,
    `| EVAL entity_euid = COALESCE(host.risk.id_value, user.risk.id_value, service.risk.id_value)`,
    `| WHERE entity_euid IS NOT NULL`,
    inRunEsql('entity_euid'),
    `| EVAL period = CASE(@timestamp <= ${now} - ${r.hours}h, "boundary", "current")`,
  ];
  if (kind === 'movers') {
    return [
      ...head,
      `| EVAL risk_score = COALESCE(host.risk.calculated_score_norm, user.risk.calculated_score_norm, service.risk.calculated_score_norm)`,
      `| STATS score = LAST(risk_score, @timestamp) BY entity_euid, period`,
      `| EVAL current_score = CASE(period == "current", score, null)`,
      `| EVAL boundary_score = CASE(period == "boundary", score, null)`,
      `| STATS current_score = MAX(current_score), boundary_score = MAX(boundary_score) BY entity_euid`,
      `| WHERE current_score IS NOT NULL AND boundary_score IS NOT NULL AND current_score - boundary_score >= 10`,
      `| STATS value = COUNT(*)`,
    ].join('\n');
  }
  return [
    ...head,
    `| EVAL risk_level = COALESCE(host.risk.calculated_level, user.risk.calculated_level, service.risk.calculated_level)`,
    `| EVAL level_num = CASE(risk_level == "Critical", 4, risk_level == "High", 3, risk_level == "Moderate", 2, risk_level == "Low", 1, 0)`,
    `| STATS level_num = LAST(level_num, @timestamp) BY entity_euid, period`,
    `| EVAL current_level_num = CASE(period == "current", level_num, null)`,
    `| EVAL boundary_level_num = CASE(period == "boundary", level_num, null)`,
    `| STATS current_level_num = MAX(current_level_num), boundary_level_num = MAX(boundary_level_num) BY entity_euid`,
    `| WHERE current_level_num >= 3 AND (boundary_level_num IS NULL OR boundary_level_num < 3)`,
    `| STATS value = COUNT(*)`,
  ].join('\n');
};

if (expected.risk) {
  for (const r of RANGES) {
    const diffs = { movers: 0, newly: 0 };
    const points = expected.risk[r.key];
    for (const point of points) {
      const [[movers]] = await esql(riskQuery('movers', r, point.hoursAgo));
      const [[newly]] = await esql(riskQuery('newly', r, point.hoursAgo));
      if (movers !== point.movers) {
        diffs.movers++;
        console.log(
          `      movers diff ${r.key} @${point.hoursAgo}h: es=${movers} expected=${point.movers}`,
        );
      }
      if (newly !== point.newlyHighCritical) {
        diffs.newly++;
        console.log(
          `      newly diff ${r.key} @${point.hoursAgo}h: es=${newly} expected=${point.newlyHighCritical}`,
        );
      }
    }
    report(
      `risk movers ${r.key}`,
      diffs.movers === 0,
      `${points.length} points, ${diffs.movers} differ`,
    );
    report(
      `risk newly high/critical ${r.key}`,
      diffs.newly === 0,
      `${points.length} points, ${diffs.newly} differ`,
    );
  }
} else {
  console.log('INFO  no risk series in the expected file (riskHistory is not series)');
}

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
