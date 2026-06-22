#!/usr/bin/env node
import {mkdir, writeFile} from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_ECOSYSTEMS = [
  'npm',
  'pypi',
  'crates',
  'nuget',
  'maven',
  'go',
  'packagist',
  'rubygems',
  'vscode',
  'openvsx',
  'repositories',
  'domains',
];

const parseArgs = (argv) => {
  const options = {output: '', ecosystems: DEFAULT_ECOSYSTEMS};
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--output') {
      options.output = argv[++i] || '';
    } else if (arg.startsWith('--output=')) {
      options.output = arg.slice('--output='.length);
    } else if (arg === '--ecosystems') {
      options.ecosystems = (argv[++i] || '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
    } else if (arg.startsWith('--ecosystems=')) {
      options.ecosystems = arg
        .slice('--ecosystems='.length)
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    }
  }
  return options;
};

const fetchLatest = async (ecosystem, token) => {
  const url = new URL('https://api.opensourcemalware.com/functions/v1/query-latest');
  url.searchParams.set('ecosystem', ecosystem);

  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`query-latest(${ecosystem}) failed with HTTP ${response.status}: ${text}`);
  }

  return JSON.parse(text);
};

const main = async () => {
  const options = parseArgs(process.argv);
  if (options.help) {
    console.log('Usage: node scripts/osm-export.mjs --output dist/osm-latest.json --ecosystems npm,pypi,...');
    return;
  }

  const token = process.env.OSM_KEY || process.env.OPEN_SOURCE_MALWARE_KEY;
  if (!token) {
    throw new Error('OSM_KEY is required');
  }

  const ecosystems = options.ecosystems.length > 0 ? options.ecosystems : DEFAULT_ECOSYSTEMS;
  const fetchedAt = new Date().toISOString();
  const ecosystemsData = {};

  for (const ecosystem of ecosystems) {
    ecosystemsData[ecosystem] = await fetchLatest(ecosystem, token);
  }

  const payload = {
    source: 'OpenSourceMalware',
    fetched_at: fetchedAt,
    ecosystems: ecosystemsData,
  };

  const json = `${JSON.stringify(payload, null, 2)}\n`;
  if (options.output) {
    await mkdir(path.dirname(options.output), {recursive: true});
    await writeFile(options.output, json, 'utf8');
  } else {
    process.stdout.write(json);
  }
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
