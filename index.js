const { request, stream, setGlobalDispatcher, Agent } = require('undici');
const EE = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const debug = require('debug')('is-my-node-vulnerable');
const satisfies = require('semver/functions/satisfies');
const { danger, vulnerableWarning, bold, separator, allGood } = require('./ascii');

setGlobalDispatcher(new Agent({ connections: 20 }));

const CORE_RAW_URL = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json'

let lastETagValue;

const coreLocalFile = path.join(__dirname, 'core.json');
const ETagFile = path.join(__dirname, '.etag');

async function readLocal(file) {
  return require(file);
}

function loadETag() {
  if (fs.existsSync(ETagFile)) {
    lastETagValue = fs.readFileSync(ETagFile).toString();
  }
}

function updateLastETag(etag) {
  lastETagValue = etag;
  fs.writeFileSync(ETagFile, lastETagValue);
}

async function fetchCoreIndex() {
  const abortRequest = new EE();
  await stream(CORE_RAW_URL, { signal: abortRequest }, ({ statusCode }) => {
    if (statusCode !== 200) {
      console.error('Request to Github failed. Aborting...');
      abortRequest.emit('abort');
      process.nextTick(() => { process.exit(1); });
    }
    return fs.createWriteStream(coreLocalFile);
  });
  return readLocal(coreLocalFile);
}

async function getCoreIndex() {
  const { headers } = await request(CORE_RAW_URL, { method: 'HEAD' });
  if (!lastETagValue || lastETagValue !== headers['etag']) {
    updateLastETag(headers['etag']);
    debug('Creating local core.json');
    return fetchCoreIndex();
  } else {
    debug('No updates from upstream. Getting a cached version.');
    return readLocal(coreLocalFile);
  }
}

function getVulnerabilityList(data) {
  const list = [];
  for (const key in data) {
    const vuln = data[key];
    if (
      satisfies(process.version, vuln.vulnerable) &&
      !satisfies(process.version, vuln.patched)
    ) {
      list.push(`${bold(vuln.cve)}: ${vuln.overview}\n${bold('Patched versions')}: ${vuln.patched}`)
    }
  }
  return list;
}

async function main() {
  loadETag();
  const coreIndex = await getCoreIndex();
  const list = getVulnerabilityList(coreIndex);
  if (list.length) {
    console.error(danger);
    console.error(vulnerableWarning + '\n');
    console.error(`${list.join(`\n${separator}\n\n`)}\n${separator}`);
    process.exit(1);
  } else {
    console.info(allGood);
  }
}

main();
