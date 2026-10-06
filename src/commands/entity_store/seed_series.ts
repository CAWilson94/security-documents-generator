export const HOUR_MS = 3_600_000;

export type RiskLevel = 'Unknown' | 'Low' | 'Moderate' | 'High' | 'Critical';

// Real Kibana risk score level boundaries (same as seed_risk_score_history.ts).
export const scoreNormToLevel = (score: number): RiskLevel => {
  if (score < 20) return 'Unknown';
  if (score < 40) return 'Low';
  if (score < 70) return 'Moderate';
  if (score < 90) return 'High';
  return 'Critical';
};

// Deterministic uniform [0,1) from an integer seed (mulberry32), so runs are reproducible.
export const rand = (seed: number): number => {
  let t = (seed + 0x6d2b79f5) | 0;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

export const clamp = (v: number): number => Math.max(0, Math.min(100, Math.round(v * 100) / 100));
export const between = (seed: number, min: number, max: number): number =>
  min + rand(seed) * (max - min);

export type SeriesRangeKey = '24h' | '7d' | '30d';

export interface SeriesRange {
  key: SeriesRangeKey;
  hours: number;
  /** Width of one sparkline bucket for this range (hourly, 6-hourly, daily). */
  bucketHours: number;
}

export const SERIES_RANGES: readonly SeriesRange[] = [
  { key: '24h', hours: 24, bucketHours: 1 },
  { key: '7d', hours: 168, bucketHours: 6 },
  { key: '30d', hours: 720, bucketHours: 24 },
];

const span = (from: number, to: number, step: number): number[] =>
  Array.from({ length: Math.floor((to - from) / step) + 1 }, (_, i) => from + i * step);

// Risk docs, in hours before now. A point at `p` compares the score at `p` with the score at
// `p + range`, so every range needs docs out to twice its length at its own resolution:
// hourly to 48h (24h range), 6-hourly to 336h (7d range), daily to 1440h (30d range).
export const RISK_GRID_HOURS: readonly number[] = [
  ...span(0, 48, 1),
  ...span(54, 336, 6),
  ...span(360, 1440, 24),
];

const GRID_INDEX = new Map(RISK_GRID_HOURS.map((hour, index) => [hour, index]));

const gridIndexOf = (hoursAgo: number): number => {
  const index = GRID_INDEX.get(hoursAgo);
  if (index === undefined) throw new Error(`${hoursAgo}h is not on the risk grid`);
  return index;
};

/** Sparkline points of a range, in hours before now (0 = now). */
export const pointHours = (range: SeriesRange): number[] => span(0, range.hours, range.bucketHours);

const RISK_STEP = 1.5;
const HIGH_SCORE = 70;
const MOVER_DELTA = 10;

/**
 * Scores on the risk grid, walking back from today's score so the entity doc stays consistent.
 * Grid times before the entity existed (`ageHours`) stay NaN and get no doc.
 */
export const riskWalk = (index: number, todayScore: number, ageHours: number): Float64Array => {
  const scores = new Float64Array(RISK_GRID_HOURS.length).fill(Number.NaN);
  scores[0] = todayScore;
  let previous = todayScore;
  let previousHour = 0;
  for (let i = 1; i < RISK_GRID_HOURS.length; i++) {
    const hour = RISK_GRID_HOURS[i];
    if (hour > ageHours) break;
    const gap = hour - previousHour;
    previous = clamp(previous + (rand(index * 131 + hour) * 2 - 1) * RISK_STEP * Math.sqrt(gap));
    scores[i] = previous;
    previousHour = hour;
  }
  return scores;
};

const SERIES_POINTS = SERIES_RANGES.map((range) =>
  pointHours(range).map((hoursAgo) => ({
    hoursAgo,
    current: gridIndexOf(hoursAgo),
    boundary: gridIndexOf(hoursAgo + range.hours),
  })),
);

export interface RiskSeriesCounts {
  movers: number[][];
  newlyHighCritical: number[][];
}

export const createRiskSeriesCounts = (): RiskSeriesCounts => ({
  movers: SERIES_POINTS.map((points) => points.map(() => 0)),
  newlyHighCritical: SERIES_POINTS.map((points) => points.map(() => 0)),
});

/**
 * Adds one entity to the expected risk series, using the shipped tile rules: a mover needs a
 * current and a boundary score at least 10 apart; newly high/critical also counts an entity
 * with no boundary score. The risk index maps calculated_score_norm as a 32-bit float, so the
 * mover difference is taken on float32-rounded scores; levels are stored as the doc's string.
 */
export const addRiskSeriesCounts = (counts: RiskSeriesCounts, scores: Float64Array): void => {
  SERIES_POINTS.forEach((points, rangeIndex) => {
    points.forEach(({ current, boundary }, pointIndex) => {
      const currentScore = scores[current];
      if (Number.isNaN(currentScore)) return;
      const boundaryScore = scores[boundary];
      const hasBoundary = !Number.isNaN(boundaryScore);
      if (hasBoundary && Math.fround(currentScore) - Math.fround(boundaryScore) >= MOVER_DELTA) {
        counts.movers[rangeIndex][pointIndex]++;
      }
      if (currentScore >= HIGH_SCORE && (!hasBoundary || boundaryScore < HIGH_SCORE)) {
        counts.newlyHighCritical[rangeIndex][pointIndex]++;
      }
    });
  });
};

export interface EventSeries {
  add: (timestampMs: number, entityIndex: number) => void;
  summarize: () => Record<
    SeriesRangeKey,
    {
      bucketHours: number;
      windowFrom: string;
      distinctEntities: number;
      buckets: Array<{ bucketStart: string; entities: number }>;
    }
  >;
}

/**
 * Distinct entities per UTC-aligned bucket, for each range, over events inside the range's
 * window (now - range .. now). Buckets with no events are omitted, like ES|QL BUCKET.
 */
export const createEventSeries = (now: number): EventSeries => {
  const perRange = SERIES_RANGES.map(() => new Map<number, Set<number>>());
  return {
    add: (timestampMs, entityIndex) => {
      SERIES_RANGES.forEach((range, rangeIndex) => {
        if (timestampMs < now - range.hours * HOUR_MS || timestampMs > now) return;
        const width = range.bucketHours * HOUR_MS;
        const start = Math.floor(timestampMs / width) * width;
        const buckets = perRange[rangeIndex];
        const entities = buckets.get(start) ?? new Set<number>();
        entities.add(entityIndex);
        buckets.set(start, entities);
      });
    },
    summarize: () => {
      const summary = {} as ReturnType<EventSeries['summarize']>;
      SERIES_RANGES.forEach((range, rangeIndex) => {
        const buckets = perRange[rangeIndex];
        const distinct = new Set<number>();
        buckets.forEach((entities) => entities.forEach((entity) => distinct.add(entity)));
        summary[range.key] = {
          bucketHours: range.bucketHours,
          windowFrom: new Date(now - range.hours * HOUR_MS).toISOString(),
          distinctEntities: distinct.size,
          buckets: [...buckets.entries()]
            .sort(([a], [b]) => a - b)
            .map(([start, entities]) => ({
              bucketStart: new Date(start).toISOString(),
              entities: entities.size,
            })),
        };
      });
      return summary;
    },
  };
};

export const summarizeRiskSeries = (counts: RiskSeriesCounts, now: number) =>
  Object.fromEntries(
    SERIES_RANGES.map((range, rangeIndex) => [
      range.key,
      SERIES_POINTS[rangeIndex].map(({ hoursAgo }, pointIndex) => ({
        hoursAgo,
        timestamp: new Date(now - hoursAgo * HOUR_MS).toISOString(),
        movers: counts.movers[rangeIndex][pointIndex],
        newlyHighCritical: counts.newlyHighCritical[rangeIndex][pointIndex],
      })),
    ]),
  );
