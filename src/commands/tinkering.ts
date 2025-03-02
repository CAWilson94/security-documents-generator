import { faker } from '@faker-js/faker';
import { ingest } from './entity-store';
import auditbeatMappings from '../mappings/auditbeat.json' assert { type: 'json' };
import { MappingTypeMapping } from '@elastic/elasticsearch/lib/api/types';

interface TinkeringEvent {
  '@timestamp': string;
  'event.ingested': string;
  name: string;
}

const EVENT_INDEX_NAME = 'auditbeat-8.12.0-2024.01.18-000001';

export const generateTinkeringData = async () => {
  try {
    const tinkeringEvents: TinkeringEvent[] = await generateTinkeringEvents();
    await ingestTinkeringEvents(tinkeringEvents);
    console.log('Tinkering data ingested');
  } catch (error) {
    console.error(error);
  }
};

export const generateTinkeringEvents = (): TinkeringEvent[] => {
  const tinkeringEvents: TinkeringEvent[] = [];
  return Array.from({ length: 20 }, () => {
    const event: TinkeringEvent = {
      '@timestamp': faker.date.recent().toISOString(),
      'event.ingested': faker.date.recent().toISOString(),
      name: faker.hacker.verb() + ' ' + faker.hacker.noun(),
    };
    tinkeringEvents.push(event);
    return event;
  });
};

export const ingestTinkeringEvents = async (events: TinkeringEvent[]) =>
  ingest(EVENT_INDEX_NAME, events, auditbeatMappings as MappingTypeMapping);
