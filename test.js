const assert = require('assert')
const { isNodeVulnerable } = require('./index')

async function t () {
  assert.ok(await isNodeVulnerable('19.0.0'))
  assert.ok(await isNodeVulnerable('18.0.0'))
  assert.ok(await isNodeVulnerable('14.0.0'))
  assert.ok(await isNodeVulnerable('16.0.0'))
}

t()
