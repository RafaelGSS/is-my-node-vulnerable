const getVersionInfo = require('./utils/get-version-info')

/**
 * @param {string} version The Node.js version to be checked.
 * @param {JSON|undefined} scheduleJson The JSON object that contains the schedule.
 * @returns {boolean} true if the version is end-of-life.
 */
function isNodeEOL (version, scheduleJson) {
  const myVersionInfo = getVersionInfo(version, scheduleJson)

  if (!myVersionInfo) {
    // i.e. isNodeEOL('abcd') or isNodeEOL('lts') or isNodeEOL('99')
    if (scheduleJson) {
      throw Error('Could not fetch version information for', version)
    }
    return true
  } else if (!myVersionInfo.end) {
    // We got a record, but..
    // v0.12.18 etc does not have an EOL date, which probably means too old.
    return true
  }

  const now = new Date()
  const end = new Date(myVersionInfo.end)
  return now > end
}

module.exports = isNodeEOL
