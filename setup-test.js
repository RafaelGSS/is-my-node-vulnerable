const isOldEnough = require('./eol-versions')
const assert = require('assert')

// When old enough an error is thrown
if (isOldEnough(process.version)) {
  runCompatibilityTest()
} else {
  require('./test')
}

function runCompatibilityTest () {
  const childProcess = require('child_process')
  const path = require('path')
  const isNodeVulnerablePath = path.resolve('./index.js')
  const child = childProcess.spawnSync(process.execPath, [isNodeVulnerablePath])
  assert.strictEqual(child.status, 1)
  assert(child.stdout.toString().indexOf('is end-of-life. There are high chances of being vulnerable') !== -1)
}
