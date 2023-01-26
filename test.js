const assert = require('assert')
const { isNodeVulnerable } = require('./index')

async function t () {
  // of course, this test is fragile
  assert.ok(await isNodeVulnerable('19.0.0'))
  assert.ok(await isNodeVulnerable('18.0.0'))
  assert.ok(await isNodeVulnerable('14.0.0'))
  assert.ok(await isNodeVulnerable('16.0.0'))

  assert.rejects(() => isNodeVulnerable('lts'), /not get exactly one version/)
  assert.rejects(() => isNodeVulnerable('999'), /not get exactly one version/)
  assert.rejects(() => isNodeVulnerable('Unobtanium'), /not get exactly one version/) // i.e. not found
  assert.rejects(() => isNodeVulnerable('20.0.0'), /not get exactly one version/)

  // EOL
  assert.ok(await isNodeVulnerable('17.0.0'))
  assert.ok(await isNodeVulnerable('15.0.0'))
  assert.ok(await isNodeVulnerable('13.0.0'))
  assert.ok(await isNodeVulnerable('12.0.0'))
  assert.ok(await isNodeVulnerable('v0.12.18'))
}

t()
