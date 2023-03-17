const core = require('@actions/core')
const { isNodeVulnerable } = require('./index')

async function run () {
  // Inputs
  const nodeVersion = core.getInput('node-version', { required: true })
  const platform = core.getInput('platform', { required: false })

  if (platform && !['linux', 'win', 'osx'].includes(platform)) {
    core.setFailed(`platform ${platform} is not valid. Please use linux, win or osx.`)
  }

  core.info(`Checking Node.js version ${nodeVersion} with platform ${platform}...`)
  const isVulnerable = await isNodeVulnerable(nodeVersion, platform)
  if (isVulnerable) {
    core.setFailed(`Node.js version ${nodeVersion} is vulnerable. Please upgrade!`)
  } else {
    core.info(`Node.js version ${nodeVersion} is OK!`)
  }
}

run()
