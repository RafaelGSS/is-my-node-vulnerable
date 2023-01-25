const assert = require('node:assert')
const { isNodeVulnerable } = require('./index')

assert.ok(isNodeVulnerable('19.0.0'))
assert.ok(isNodeVulnerable('18.0.0'))
assert.ok(isNodeVulnerable('14.0.0'))
assert.ok(isNodeVulnerable('16.0.0'))
