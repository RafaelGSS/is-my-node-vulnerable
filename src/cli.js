const { allGood, danger, separator, vulnerableWarning } = require('./ascii')
const isNodeEOL = require('./is-node-eol')

const checkPlatform = require('./utils/check-platform')
const getJson = require('./utils/get-json')
const getVulnerabilityList = require('./utils/get-vulnerability-list')
const loadETag = require('./utils/load-etag')

const STORE = require('./store')

async function cli (version, platform) {
  checkPlatform(platform)

  const scheduleJson = await getJson(STORE.schedule)
  const isEOL = isNodeEOL(version, scheduleJson)

  if (isEOL) {
    console.error(danger)
    console.error(`${version} is end-of-life. There are high chances of being vulnerable. Please upgrade it.`)
    process.exit(1)
  }

  const securityJson = await getJson(STORE.security)
  const list = getVulnerabilityList(version, securityJson, platform)

  if (list.length) {
    console.error(danger)
    console.error(vulnerableWarning + '\n')
    console.error(`${list.join(`\n${separator}\n\n`)}\n${separator}`)
    process.exit(1)
  } else {
    console.info(allGood)
  }
}

if (process.argv[2] !== '-r') {
  loadETag()
}

module.exports = cli
