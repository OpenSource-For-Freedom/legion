#!/usr/bin/env node
import {mkdir, writeFile} from 'node:fs/promises';
import path from 'node:path';

const SOURCES = {
  spamhaus_drop: 'https://defcondatabase.com/data/threat_intel/spamhaus_drop.json',
  abuseipdb_blacklist: 'https://defcondatabase.com/data/threat_intel/abuseipdb_blacklist.json',
};

const parseArgs = (argv) => {
  const options = {output: '', help: false};
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--output') {
      options.output = argv[++i] || '';
    } else if (arg.startsWith('--output=')) {
      options.output = arg.slice('--output='.length);
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    }
  }
  return options;
};

const fetchJson = async (url) => {
  const response = await fetch(url, {
    method: 'GET',
    headers: {Accept: 'application/json'},
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`fetch failed for ${url}: HTTP ${response.status}: ${text}`);
  }
  return JSON.parse(text);
};

const main = async () => {
  const options = parseArgs(process.argv);
  if (options.help) {
    console.log('Usage: node scripts/defcon-export.mjs --output dist/defcon-threat-intel.json');
    return;
  }

  const fetchedAt = new Date().toISOString();
  const payload = {
    source: 'DEFCON Database',
    fetched_at: fetchedAt,
    feeds: {
      spamhaus_drop: await fetchJson(SOURCES.spamhaus_drop),
      abuseipdb_blacklist: await fetchJson(SOURCES.abuseipdb_blacklist),
    },
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
