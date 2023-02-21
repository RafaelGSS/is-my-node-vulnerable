const core = require('@actions/core')
const { isNodeVulnerable } = require('./index')

async function run () {
  // Inputs
  const nodeVersion = core.getInput('node-version', { required: true })
  core.info(`Checking Node.js version ${nodeVersion}...`)
  const isVulnerable = await isNodeVulnerable(nodeVersion)
  if (isVulnerable) {
    core.setFailed(`Node.js version ${nodeVersion} is vulnerable. Please upgrade!`)
  } else {
    core.info(`Node.js version ${nodeVersion} is OK!`)
  }
}

run()
