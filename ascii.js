const clc = require('cli-color')

const danger = '\n' +
'\n' +
'██████   █████  ███    ██  ██████  ███████ ███████\n' +
'██   ██ ██   ██ ████   ██ ██       ██      ██   ██\n' +
'██   ██ ███████ ██ ██  ██ ██   ███ █████   ███████\n' +
'██   ██ ██   ██ ██  ██ ██ ██    ██ ██      ██   ██\n' +
'██████  ██   ██ ██   ████  ██████  ███████ ██   ██\n' +
'\n'

const allGood = '\n' +
'\n' +
' █████  ██      ██           ██████   ██████   ██████  ██████         ██\n' +
'██   ██ ██      ██          ██       ██    ██ ██    ██ ██   ██     ██  ██\n' +
'███████ ██      ██          ██   ███ ██    ██ ██    ██ ██   ██         ██\n' +
'██   ██ ██      ██          ██    ██ ██    ██ ██    ██ ██   ██     ██  ██\n' +
'██   ██ ███████ ███████      ██████   ██████   ██████  ██████         ██\n' +
'\n'

const bold = clc.bold

const vulnerableWarning = bold('The current Node.js version (' + process.version + ') is vulnerable to the following CVEs:')

let separator = '='
for (let i = 0; i < process.stdout.columns; ++i) {
  separator = separator + '='
}

module.exports.danger = danger
module.exports.allGood = allGood
module.exports.bold = bold
module.exports.vulnerableWarning = vulnerableWarning
module.exports.separator = separator
