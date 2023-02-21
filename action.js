const core = require("@actions/core");
const { isNodeVulnerable } = require('./index')

async function run () {

  // Inputs
  const nodeVersion = core.getInput('node-version', { required: true })
  if(isNodeVulnerable(nodeVersion)){
    core.setFailed(`Node.js version ${nodeVersion} is vulnerable`)
  }

}

run()