const clc = require('cli-color')

const danger = `
                                                   
██████   █████  ███    ██  ██████  ███████ ██████  
██   ██ ██   ██ ████   ██ ██       ██      ██   ██ 
██   ██ ███████ ██ ██  ██ ██   ███ █████   ██████  
██   ██ ██   ██ ██  ██ ██ ██    ██ ██      ██   ██ 
██████  ██   ██ ██   ████  ██████  ███████ ██   ██ 
                                                   
`

const allGood = `
                                                                          
 █████  ██      ██           ██████   ██████   ██████  ██████         ██  
██   ██ ██      ██          ██       ██    ██ ██    ██ ██   ██     ██  ██ 
███████ ██      ██          ██   ███ ██    ██ ██    ██ ██   ██         ██ 
██   ██ ██      ██          ██    ██ ██    ██ ██    ██ ██   ██     ██  ██ 
██   ██ ███████ ███████      ██████   ██████   ██████  ██████         ██  
                                                                          
`

const bold = clc.bold

const vulnerableWarning = bold(`The current Node.js version (${process.version}) is vulnerable to the following CVEs:`)

const separator = '='.repeat(process.stdout.columns)

module.exports = {
  danger,
  allGood,
  bold,
  vulnerableWarning,
  separator
}
