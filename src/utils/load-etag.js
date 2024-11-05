const STORE = require('../store')
const debug = require('./debug')
const fs = require('fs')

function loadETag () {
  for (const [key, obj] of Object.entries(STORE)) {
    if (fs.existsSync(obj.etagFile)) {
      debug(`Loading local ETag for '${key}'`)
      obj.etagValue = fs.readFileSync(obj.etagFile).toString()
    }
  }
}

module.exports = loadETag
