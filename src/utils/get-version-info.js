const STORE = require('../store')
const fs = require('fs')

function getVersionInfo (version, scheduleJson) {
  if (!scheduleJson) {
    scheduleJson = fs.readFileSync(STORE.schedule.jsonFile)
  }

  // Gets the version key, i.e. 'v0.12' for 'v0.12.18', or 'v12' for 'v12.22.12'
  const separator = '.'
  const sections = version.split(separator)
  const versionKey = sections[0] === 'v0' ? sections.slice(0, 2).join(separator) : sections[0]

  if (scheduleJson[versionKey]) {
    return scheduleJson[versionKey]
  }

  return null
}

module.exports = getVersionInfo
