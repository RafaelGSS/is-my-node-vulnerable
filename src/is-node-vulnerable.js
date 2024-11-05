const isNodeEOL = require('./is-node-eol')
const STORE = require('./store')

const checkPlatform = require('./utils/check-platform')
const getJson = require('./utils/get-json')
const getVulnerabilityList = require('./utils/get-vulnerability-list')

async function isNodeVulnerable (version, platform) {
  checkPlatform(platform)

  const scheduleJson = await getJson(STORE.schedule)
  const isEOL = isNodeEOL(version, scheduleJson)

  if (isEOL) {
    return true
  }

  const securityJson = await getJson(STORE.security)
  const list = getVulnerabilityList(version, securityJson, platform)

  return list.length > 0
}

module.exports = isNodeVulnerable
