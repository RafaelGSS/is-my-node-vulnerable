const { danger, allGood, bold, vulnerableWarning, separator } = require('./ascii')
const { request } = require('https')
const fs = require('fs')
const path = require('path')
const satisfies = require('semver/functions/satisfies')
const nv = require('@pkgjs/nv')

const CORE_RAW_URL = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json'

let lastETagValue

const coreLocalFile = path.join(__dirname, 'core.json')
const ETagFile = path.join(__dirname, '.etag')

async function readLocal (file) {
  return require(file)
}

function debug (msg) {
  if (process.env.DEBUG) {
    console.debug(msg)
  }
}

function loadETag () {
  if (fs.existsSync(ETagFile)) {
    debug('Loading local ETag')
    lastETagValue = fs.readFileSync(ETagFile).toString()
  }
}

function updateLastETag (etag) {
  lastETagValue = etag
  fs.writeFileSync(ETagFile, lastETagValue)
}

async function fetchCoreIndex () {
  await new Promise((resolve) => {
    request(CORE_RAW_URL, (res) => {
      if (res.statusCode !== 200) {
        console.error(`Request to Github returned http status ${res.statusCode}. Aborting...`)
        process.nextTick(() => { process.exit(1) })
      }

      const fileStream = fs.createWriteStream(coreLocalFile)
      res.pipe(fileStream)

      fileStream.on('finish', () => {
        fileStream.close()
        resolve()
      })

      fileStream.on('error', (err) => {
        console.error(`Error ${err.message} while writing to '${coreLocalFile}'. Aborting...`)
        process.nextTick(() => { process.exit(1) })
      })
    }).on('error', (err) => {
      console.error(`Request to Github returned error ${err.message}. Aborting...`)
      process.nextTick(() => { process.exit(1) })
    }).end()
  })
  return readLocal(coreLocalFile)
}

async function getCoreIndex () {
  return new Promise((resolve) => {
    const req = request(CORE_RAW_URL, { method: 'HEAD' }, (res) => {
      if (res.statusCode !== 200) {
        console.error(`Request to Github returned http status ${res.statusCode}. Aborting...`)
        process.nextTick(() => { process.exit(1) })
      }

      res.on('data', () => {})

      const { etag } = res.headers
      if (!lastETagValue || lastETagValue !== etag || !fs.existsSync(coreLocalFile)) {
        updateLastETag(etag)
        debug('Creating local core.json')
        resolve(fetchCoreIndex())
      } else {
        debug(`No updates from upstream. Getting a cached version: ${coreLocalFile}`)
        resolve(readLocal(coreLocalFile))
      }
    })

    req.on('error', (err) => {
      console.error(`Request to Github returned error ${err.message}. Aborting...`)
      process.nextTick(() => { process.exit(1) })
    })

    req.end()
  })
}

const checkPlatform = platform => {
  const availablePlatforms = ['aix', 'darwin', 'freebsd', 'linux', 'openbsd', 'sunos', 'win32', 'android']
  if (platform && !availablePlatforms.includes(platform)) {
    throw new Error(`platform ${platform} is not valid. Please use ${availablePlatforms.join(',')}.`)
  }
}
const isSystemAffected = (platform, affectedEnvironments) => {
  // No platform specified (legacy mode)
  if (!platform || !Array.isArray(affectedEnvironments)) {
    return true
  }
  // If the environment is matching or all the environments are affected
  if (affectedEnvironments.includes(platform) || affectedEnvironments.includes('all')) {
    return true
  }
  // Default to false
  return false
}

function getVulnerabilityList (currentVersion, data, platform) {
  const list = []
  for (const key in data) {
    const vuln = data[key]

    if (
      (
        satisfies(currentVersion, vuln.vulnerable) &&
        !satisfies(currentVersion, vuln.patched)
      ) && isSystemAffected(platform, vuln.affectedEnvironments)
    ) {
      const severity = vuln.severity === 'unknown' ? '' : `(${vuln.severity})`
      list.push(`${bold(vuln.cve)}${severity}: ${vuln.overview}\n${bold('Patched versions')}: ${vuln.patched}`)
    }
  }
  return list
}

async function cli (currentVersion, platform) {
  checkPlatform(platform)
  const isEOL = await isNodeEOL(currentVersion)
  if (isEOL) {
    console.error(danger)
    console.error(`${currentVersion} is end-of-life. There are high chances of being vulnerable. Please upgrade it.`)
    process.exit(1)
  }

  const coreIndex = await getCoreIndex()
  const list = getVulnerabilityList(currentVersion, coreIndex, platform)
  if (list.length) {
    console.error(danger)
    console.error(vulnerableWarning + '\n')
    console.error(`${list.join(`\n${separator}\n\n`)}\n${separator}`)
    process.exit(1)
  } else {
    console.info(allGood)
  }
}

/**
 * @param {string} version
 * @returns {Promise<boolean>} true if the version is end-of-life
 */
async function isNodeEOL (version) {
  const myVersionInfo = await nv(version)
  if (!myVersionInfo) {
    // i.e. isNodeEOL('abcd')
    throw Error(`Could not fetch version information for ${version}`)
  } else if (myVersionInfo.length !== 1) {
    // i.e. isNodeEOL('lts') or isNodeEOL('99')
    throw Error(`Did not get exactly one version record for ${version}`)
  } else if (!myVersionInfo[0].end) {
    // We got a record, but..
    // v0.12.18 etc does not have an EOL date, which probably means too old.
    return true
  }
  const now = new Date()
  const end = new Date(myVersionInfo[0].end)
  return now > end
}

async function isNodeVulnerable (version, platform) {
  checkPlatform(platform)
  const isEOL = await isNodeEOL(version)
  if (isEOL) {
    return true
  }

  const coreIndex = await getCoreIndex()
  const list = getVulnerabilityList(version, coreIndex, platform)
  return list.length > 0
}

if (process.argv[2] !== '-r') {
  loadETag()
}

module.exports = {
  isNodeVulnerable,
  cli
}
