#! /usr/bin/env node
import { program } from 'commander';
import {
  generateAlerts,
  deleteAllAlerts,
  deleteAllEvents,
  generateGraph,
  generateEvents,
} from './commands/documents';
import { setupEntityResolutionDemo } from './commands/entity_resolution';
import { generateLegacyRiskScore } from './commands/legacy_risk_score';
import { kibanaApi } from './utils/';
import { cleanEntityStore, generateEntityStore } from './commands/entity-store';
import {
  createPerfDataFile,
  uploadPerfDataFile,
  uploadPerfDataFileInterval,
  listPerfDataFiles,
} from './commands/entity-store-perf';
import { checkbox, select, input } from '@inquirer/prompts';
import { ENTITY_STORE_OPTIONS, generateNewSeed } from './constants';
import { initializeSpace } from './utils/initialize_space';
import { generateAssetCriticality } from './commands/asset_criticality';

const parseIntBase10 = (input: string) => parseInt(input, 10);

program
  .command('generate-alerts')
  .option('-n <n>', 'number of alerts')
  .option('-h <h>', 'number of hosts')
  .option('-u <h>', 'number of users')
  .option('-s <h>', 'space (will be created if it does not exist)')
  .description('Generate fake alerts')
  .action(async (options) => {
    const alertsCount = parseInt(options.n || 1);
    const hostCount = parseInt(options.h || 1);
    const userCount = parseInt(options.u || 1);
    const space = options.s || 'default';

    if (space !== 'default') {
      await initializeSpace(space);
    }

    generateAlerts(alertsCount, userCount, hostCount, space);
  });

program
  .command('generate-events')
  .argument('<n>', 'integer argument', parseIntBase10)
  .description('Generate events')
  .action(generateEvents);

program
  .command('generate-graph')
  .description('Generate fake graph')
  .action(generateGraph);

program
  .command('delete-alerts')
  .description('Delete all alerts')
  .action(deleteAllAlerts);

program
  .command('delete-events')
  .description('Delete all events')
  .action(deleteAllEvents);

program
  .command('test-risk-score')
  .description('Test risk score API')
  .action(kibanaApi.fetchRiskScore);

program
  .command('create-perf-data')
  .argument('<name>', 'name of the file')
  .argument('<entity-count>', 'number of entities', parseIntBase10)
  .argument('<logs-per-entity>', 'number of logs per entity', parseIntBase10)
  .argument(
    '[start-index]',
    'for sequential data, which index to start at',
    parseIntBase10,
    0,
  )
  .description('Create performance data')
  .action((name, entityCount, logsPerEntity, startIndex) => {
    createPerfDataFile({ name, entityCount, logsPerEntity, startIndex });
  });

program
  .command('upload-perf-data')
  .argument('[file]', 'File to upload')
  .option('--index <index>', 'Destination index')
  .option('--delete', 'Delete all entities before uploading')
  .description('Upload performance data file')
  .action(async (file, options) => {
    let selectedFile = file;

    if (!selectedFile) {
      const files = await listPerfDataFiles();

      if (files.length === 0) {
        console.log('No files to upload');
        process.exit(1);
      }

      const userSelectedFile = await select({
        message: 'Select a file to upload',
        choices: files.map((file) => ({ name: file, value: file })),
      });

      selectedFile = userSelectedFile;
    }

    await uploadPerfDataFile(selectedFile, options.index, options.delete);
  });

program
  .command('upload-perf-data-interval')
  .argument('[file]', 'File to upload')
  .option('--interval <interval>', 'interval in s', parseIntBase10, 30)
  .option('--count <count>', 'number of times to upload', parseIntBase10, 10)
  .option('--deleteData', 'Delete all entities before uploading')
  .option('--deleteEngines', 'Delete all entities before uploading')
  .description('Upload performance data file')
  .action(async (file, options) => {
    let selectedFile = file;

    if (!selectedFile) {
      const files = await listPerfDataFiles();

      if (files.length === 0) {
        console.log('No files to upload');
        process.exit(1);
      }

      const userSelectedFile = await select({
        message: 'Select a file to upload',
        choices: files.map((file) => ({ name: file, value: file })),
      });

      selectedFile = userSelectedFile;
    }

    await uploadPerfDataFileInterval(
      selectedFile,
      options.interval * 1000,
      options.count,
      options.deleteData,
      options.deleteEngines,
    );
  });

program
  .command('entity-resolution-demo')
  .option('--mini', 'Only load the mini dataset', false)
  .option('--delete', 'Delete old data', false)
  .option('--keep-emails', 'No Email variants', false)
  .description('Load entity resolution demo data')
  .action(({ mini, deleteData, keepEmails }) => {
    setupEntityResolutionDemo({ mini, deleteData, keepEmails });
  });

program
  .command('entity-store')
  .description('Generate entity store')
  .action(async () => {
    const entityStoreAnswers = await checkbox<
      keyof typeof ENTITY_STORE_OPTIONS
    >({
      message: 'Select options',
      choices: [
        {
          name: 'Seed (stable random data)',
          value: ENTITY_STORE_OPTIONS.seed,
          checked: true,
        },
        {
          name: 'Assign asset criticality',
          value: ENTITY_STORE_OPTIONS.criticality,
          checked: true,
        },
        {
          name: 'Enable Risk Engine',
          value: ENTITY_STORE_OPTIONS.riskEngine,
          checked: true,
        },
        {
          name: 'Create detection rule',
          value: ENTITY_STORE_OPTIONS.rule,
          checked: true,
        },
        {
          name: 'Generate fake elastic agents for hosts',
          value: ENTITY_STORE_OPTIONS.agent,
          checked: false,
        },
      ],
    });

    const userCount = await input({
      message: 'How many users',
      default: '10',
    });

    const hostCount = await input({
      message: 'How many hosts',
      default: '10',
    });

    const serviceCount = await input({
      message: 'How many services',
      default: '10',
    });

    const seed = generateNewSeed() + '';

    let seedAnswer = seed;

    if (entityStoreAnswers.includes(ENTITY_STORE_OPTIONS.seed)) {
      seedAnswer = await input({
        message:
          'Enter seed to generate stable random data or <enter> to use a new seed',
        default: seed,
      });
    }

    generateEntityStore({
      users: parseIntBase10(userCount),
      hosts: parseIntBase10(hostCount),
      services: parseIntBase10(serviceCount),
      seed: parseIntBase10(seedAnswer),
      options: entityStoreAnswers,
    });
  });

program
  .command('clean-entity-store')
  .description('clean entity store')
  .action(cleanEntityStore);

program
  .command('generate-asset-criticality')
  .option('-h <h>', 'number of hosts')
  .option('-u <u>', 'number of users')
  .description('Generate asset criticality for entities')
  .action(async (options) => {
    const users = parseInt(options.u || 10);
    const hosts = parseInt(options.h || 10);

    generateAssetCriticality({ users, hosts });
  });

program
  .command('generate-legacy-risk-score')
  .description('Install legacy risk score and generate data')
  .action(generateLegacyRiskScore);

program.parse();
