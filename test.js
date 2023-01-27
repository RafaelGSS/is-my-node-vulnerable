const assert = require('assert')
const { isNodeVulnerable, isNodeEOL, isNodeSupportedMajor } = require('./index')

async function t () {
  // of course, this test is fragile
  assert.ok(await isNodeVulnerable('19.0.0'))
  assert.ok(await isNodeVulnerable('18.0.0'))
  assert.ok(await isNodeVulnerable('14.0.0'))
  assert.ok(await isNodeVulnerable('16.0.0'))

  assert.rejects(() => isNodeEOL('lts'), /not get exactly one version/)
  assert.rejects(() => isNodeEOL('999'), /not get exactly one version/)
  assert.rejects(() => isNodeEOL('Unobtanium'), /not get exactly one version/) // i.e. not found

  assert.ok(!await isNodeEOL('19.0.0'))
  assert.ok(!await isNodeEOL('18.0.0'))
  assert.ok(!await isNodeEOL('16.0.0'))
  assert.ok(await isNodeEOL('15.0.0'))
  assert.ok(!await isNodeEOL('14.0.0'))
  assert.ok(await isNodeEOL('13.0.0'))
  assert.ok(await isNodeEOL('12.0.0'))
  assert.ok(await isNodeEOL('0.12.18'))

  assert.ok(!await isNodeSupportedMajor('20.0.0'))
  assert.ok(await isNodeSupportedMajor('19.0.0'))
  assert.ok(await isNodeSupportedMajor('18.0.0'))
  assert.ok(!await isNodeSupportedMajor('17.0.0'))
  assert.ok(await isNodeSupportedMajor('16.0.0'))
  assert.ok(!await isNodeSupportedMajor('15.0.0'))
  assert.ok(await isNodeSupportedMajor('14.0.0'))
  assert.ok(!await isNodeSupportedMajor('13.0.0'))
  assert.ok(!await isNodeSupportedMajor('12.0.0'))
  assert.ok(!await isNodeSupportedMajor('v0.12.18'))
}

t()
