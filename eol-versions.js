// Sync from https://raw.githubusercontent.com/nodejs/Release/master/schedule.json
// These are the list of versions that might be affected by this module dependencies
const versionMap = {
  // v0.12
  v0: {
    start: '2015-02-06',
    end: '2016-12-31'
  },
  v4: {
    start: '2015-09-08',
    lts: '2015-10-12',
    maintenance: '2017-04-01',
    end: '2018-04-30',
    codename: 'Argon'
  },
  v5: {
    start: '2015-10-29',
    maintenance: '2016-04-30',
    end: '2016-06-30'
  },
  v6: {
    start: '2016-04-26',
    lts: '2016-10-18',
    maintenance: '2018-04-30',
    end: '2019-04-30',
    codename: 'Boron'
  },
  v7: {
    start: '2016-10-25',
    maintenance: '2017-04-30',
    end: '2017-06-30'
  },
  v8: {
    start: '2017-05-30',
    lts: '2017-10-31',
    maintenance: '2019-01-01',
    end: '2019-12-31',
    codename: 'Carbon'
  },
  v9: {
    start: '2017-10-01',
    maintenance: '2018-04-01',
    end: '2018-06-30'
  },
  v10: {
    start: '2018-04-24',
    lts: '2018-10-30',
    maintenance: '2020-05-19',
    end: '2021-04-30',
    codename: 'Dubnium'
  },
  v11: {
    start: '2018-10-23',
    maintenance: '2019-04-22',
    end: '2019-06-01'
  },
  v12: {
    start: '2019-04-23',
    lts: '2019-10-21',
    maintenance: '2020-11-30',
    end: '2022-04-30',
    codename: 'Erbium'
  },
  v13: {
    start: '2019-10-22',
    maintenance: '2020-04-01',
    end: '2020-06-01'
  },
  v14: {
    start: '2020-04-21',
    lts: '2020-10-27',
    maintenance: '2021-10-19',
    end: '2023-04-30',
    codename: 'Fermium'
  },
  v15: {
    start: '2020-10-20',
    maintenance: '2021-04-01',
    end: '2021-06-01'
  },
  v16: {
    start: '2021-04-20',
    lts: '2021-10-26',
    maintenance: '2022-10-18',
    end: '2023-09-11',
    codename: 'Gallium'
  },
  v17: {
    start: '2021-10-19',
    maintenance: '2022-04-01',
    end: '2022-06-01'
  },
  v19: {
    start: '2022-10-18',
    maintenance: '2023-04-01',
    end: '2023-06-01'
  }
}

function isOldEnough (version) {
  const versionInfo = getVersionInfo(version)

  if (!versionInfo) {
    return false
  } else if (!versionInfo.end) {
    return true // Versions without an EOL date are considered EOL
  }

  const now = new Date()
  const end = new Date(versionInfo.end)
  return now > end
}

function getVersionInfo (version) {
  const majorVersion = extractMajorVersion(version)
  return versionMap[majorVersion] || null
}

function extractMajorVersion (version) {
  // Extracts the major version number from a version string like 'v12.22.12'
  const major = version.split('.')[0]
  return major
}

module.exports = isOldEnough
