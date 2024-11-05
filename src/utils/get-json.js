const { request } = require('https')
const debug = require('./debug')
const fetchJson = require('./fetch-json')
const fs = require('fs')

async function getJson (obj) {
  return new Promise((resolve) => {
    request(obj.url, { method: 'HEAD' }, (res) => {
      if (res.statusCode !== 200) {
        console.error(`Request to Github returned http status ${res.statusCode}. Aborting...`)
        process.nextTick(() => { process.exit(1) })
      }

      res.on('data', () => {})

      const { etag } = res.headers
      if (!obj.etagValue || obj.eTagValue !== etag || !fs.existsSync(obj.jsonFile)) {
        obj.etagValue = etag
        fs.writeFileSync(obj.etagFile, etag)
        debug('Creating local core.json')
        resolve(fetchJson(obj))
      } else {
        debug(`No updates from upstream. Getting a cached version: ${obj.jsonFile}`)
        resolve(require(obj.jsonFile))
      }
    }).on('error', (err) => {
      console.error(`Request to Github returned error ${err.message}. Aborting...`)
      process.nextTick(() => { process.exit(1) })
    }).end()
  })
}

module.exports = getJson
