---
name: seed-ea
description: Populate Entity Analytics pages using security-documents-generator. Helps pick the right commands for the EA pages or data you want to seed.
---

# Seed EA Data

Use `security-documents-generator` to populate Entity Analytics pages for development or testing.

Run commands from the repo root with: `yarn start <command>`

Before running any command, ensure the correct Node version is active. The repo includes an `.nvmrc` pinned to the required version — if you have nvm installed, run `nvm use` from the repo root first to avoid version mismatch errors.

## Input

The user will either:
- Name a specific EA page or feature they want to populate (e.g. "home page", "flyouts", "PUM", "AI summary")
- Ask for a full end-to-end seed of all EA pages
- Provide flags or modifications (e.g. "more hosts", "non-default space", "skip setup")
- Ask what command to use for something specific
- Specify a target cluster (e.g. "seed into my BC environment" or "use the cloud deployment in config.bc.json")

If no input is given, ask what they want to populate. If a target cluster is mentioned, remind the user that the generator reads from `config.json` in the repo root — they should ensure that file points to the right cluster before running.

## Page → Command Mapping

Use this to recommend the right command(s):

| Page / Feature | Command(s) |
|---|---|
| Home page — entities table, risk KPI/history, watchlists | `risk-score-v2` |
| Entity store management page | `risk-score-v2` (sets up entity store) |
| Asset criticality | `risk-score-v2` (includes criticality) or `generate-asset-criticality` separately |
| Privileged user monitoring | `privmon-quick` or `privileged-user-monitoring` (interactive) |
| Threat hunting leads | `leads` (interactive, needs inference connector pre-configured) |
| AI summary / anomalies panel | `generate-entity-ai-insights --v2 --correlate-with-entity-store` |
| Entity flyouts — host/user/service right panels | `generate-entity-maintainers-data --quick` + `generate-entity-ai-insights --v2` |
| Entity flyout — generic right panel | `quick-entity-store` (includes generic; `risk-score-v2` does not) |
| Explore pages (hosts/users/network) | Covered by `risk-score-v2` alerts; top up with `generate-alerts` if empty |
| Risk score history snapshots | `generate-entity-maintainers-data --quick` |
| CSP / cloud posture findings | `csp --data-sources elastic_all --csp-scores` |
| All EA pages end-to-end | See full sequence below |

## Full End-to-End Sequence

When the user wants everything populated, recommend these in order:

```bash
# 1. Core: entity store, risk engine, criticality, watchlists
yarn start risk-score-v2 --entity-kinds host,idp_user,local_user,service --hosts 20 --users 20 --services 10 --alerts-per-entity 10

# 2. Risk history + relationships + anomaly behaviours (flyouts, home history panel)
yarn start generate-entity-maintainers-data --space default --quick

# 3. Privileged user monitoring
yarn start privmon-quick --space default

# 4. AI insights + anomaly records (ai_summary, flyout panels)
yarn start generate-entity-ai-insights --v2 --correlate-with-entity-store -h 20 -u 20 -s default

# 5. Threat hunting leads (requires inference connector pre-configured in Kibana)
yarn start leads --space default
# → choose "Generate leads now"

# 6. Generic entities (for generic flyout — not covered by risk-score-v2)
yarn start quick-entity-store --space default
```

## Key Flags

- `--no-setup` — skip entity store installation (use when already installed)
- `--space <id>` — target a non-default space
- `--dangerous-clean` — wipe existing data before seeding (use with care)
- `--perf` — scale preset: 1000 users, 1000 hosts, 50 alerts each
- `--hosts <n>` / `--users <n>` / `--services <n>` — control entity counts
- `--alerts-per-entity <n>` — controls how many alerts drive risk scoring

## Scale and sparkline tests (`seed-direct-bulk`)

`seed-direct-bulk` writes entities, risk history, alerts and anomalies straight into Elasticsearch (it skips Kibana), so large runs are fast (about 66k risk docs/s locally). Entity Store v2 must already be installed (`risk-score-v2` or the entity-store install does it). It is for the Needs Attention tiles (NAT) scale and sparkline experiments, not for populating pages for demos.

```bash
# Size ladder from telemetry (v2 spaces, 2026-10-06): p75 ~ 20k entities / 22k alerts / 30k anomalies;
# p90 ~ 200k entities / 170k alerts / 90k anomalies (see the vault note NAT-telemetry-sizing-2026-10-06).
yarn start seed-direct-bulk --entities 20000 --alerts-total 22000 --anomalies-total 30000 \
  --risk-history series --alert-profile uniform --alert-entity-fraction 0.5 --watchlisted-rate 0.1 \
  --expected-out expected.json --expected-series-out expected-series.json

# Check what Elasticsearch holds against what was intended (run right after seeding)
node scripts/verify_seed_series.mjs expected-series.json
```

Flags that matter for sparklines:
- `--risk-history series` writes risk docs on the bucket grid (hourly to 48h, 6-hourly to 14d, daily to 60d) from each entity's first_seen: about 119 docs per entity on average (143 for entities older than 60 days), so 20k entities is about 2.4M docs. Default `boundaries` writes 7 fixed docs.
- `--alert-profile uniform` spreads alerts and anomalies evenly over `--alert-horizon-days` (default 30); `slots` puts equal counts in six windows of different length.
- `--alert-entity-fraction` below 1 makes alerts repeat on the same entities.
- `--watchlisted-rate` creates a watchlist through Kibana and puts it on that share of the alert-eligible entities, so the Watchlisted tile is not 0.
- In series mode `--cur-mover-rate` and the other mover/newly-high rates only shape each entity's score today; mover counts at each point come from the score walk.
- `--expected-series-out` writes the expected per-bucket series (UTC-aligned, like ES|QL `BUCKET`) that `verify_seed_series.mjs` checks.

Things to know before trusting a run:
- Seeded data goes stale after about an hour for the live tile queries (the verifier pins `NOW()` so it is not affected).
- The risk index stores scores as 32-bit floats, and ES|QL `COUNT_DISTINCT` is approximate (observed up to about 0.7% off at 10k distinct entities), so tile counts can differ slightly from the exact expected values.
- Index names and the `.entities.v2.latest.security_<space>` alias are assumed; re-seeding overwrites entity docs.

## Known Gaps

- **Generic flyout**: `risk-score-v2` doesn't seed generic entities — use `quick-entity-store` instead
- **Threat hunting leads**: requires an inference connector to be set up in Kibana first
- **Anomalies panel**: `generate-entity-ai-insights` seeds anomaly *records* but doesn't run actual ML jobs

## Output

Give the user the exact `yarn start` command(s) to run, with a note on what each one populates. If they want to run them, offer to do so using Bash from the repo root. Always confirm before running any command with `--dangerous-clean`.
