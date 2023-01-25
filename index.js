const { request, stream, setGlobalDispatcher, Agent } = require('undici');
const EE = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const semver = require('semver');

setGlobalDispatcher(new Agent({ connections: 20 }));

const CORE_RAW_URL = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json'

let lastETagValue;

const coreLocalFile = path.join(__dirname, 'core.json');
const ETagFile = path.join(__dirname, '.etag');

async function readLocal(file) {
  return fs.createReadStream(file);
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
    console.info('Creating local core.json');
    // TODO: create local
    return fetchCoreIndex();
  } else {
    console.info('No updates from upstream. Getting a cached version.');
    return readLocal(coreLocalFile);
  }
}

async function main() {
  loadETag();
  const coreIndex = await getCoreIndex();
  const JSONTransformStream = new TransformStream({
    transform: (chunk, controller) => {
      controller.enqueue(chunk);
    }
  })
  coreIndex.pipe(JSONTransformStream)
}

main();
