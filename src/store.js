const path = require('path')

const CACHE_DIR = path.join(__dirname, 'cache')

module.exports = {
  security: {
    url: 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json',
    jsonFile: path.join(CACHE_DIR, 'security.json'),
    etagFile: path.join(CACHE_DIR, 'security.etag'),
    etagValue: ''
  },
  schedule: {
    url: 'https://raw.githubusercontent.com/nodejs/Release/main/schedule.json',
    jsonFile: path.join(CACHE_DIR, 'schedule.json'),
    etagFile: path.join(CACHE_DIR, 'schedule.etag'),
    etagValue: ''
  }
}
