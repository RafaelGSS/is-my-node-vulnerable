const assert = require('assert')
const { isNodeVulnerable, isNodeDefinitelyEOL, isNodeSupportedMajor } = require('./index')

async function t () {
  assert.ok(await isNodeVulnerable('19.0.0'))
  assert.ok(await isNodeVulnerable('18.0.0'))
  assert.ok(await isNodeVulnerable('14.0.0'))
  assert.ok(await isNodeVulnerable('16.0.0'))

  assert.ok(!await isNodeDefinitelyEOL('19.0.0'))
  assert.ok(!await isNodeDefinitelyEOL('18.0.0'))
  assert.ok(!await isNodeDefinitelyEOL('16.0.0'))
  assert.ok(!await isNodeDefinitelyEOL('15.0.0'))
  assert.ok(!await isNodeDefinitelyEOL('14.0.0'))
  assert.ok(await isNodeDefinitelyEOL('13.0.0'))
  assert.ok(await isNodeDefinitelyEOL('12.0.0'))
  assert.ok(await isNodeDefinitelyEOL('v0.12.18'))

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
