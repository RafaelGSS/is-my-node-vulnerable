const { request } = require('https')
const fs = require('fs')

async function fetchJson (obj) {
  await new Promise((resolve) => {
    request(obj.url, (res) => {
      if (res.statusCode !== 200) {
        console.error(`Request to Github returned http status ${res.statusCode}. Aborting...`)
        process.nextTick(() => { process.exit(1) })
      }

      const fileStream = fs.createWriteStream(obj.jsonFile)
      res.pipe(fileStream)

      fileStream.on('finish', () => {
        fileStream.close()
        resolve()
      })

      fileStream.on('error', (err) => {
        console.error(`Error ${err.message} while writing to '${obj.jsonFile}'. Aborting...`)
        process.nextTick(() => { process.exit(1) })
      })
    }).on('error', (err) => {
      console.error(`Request to Github returned error ${err.message}. Aborting...`)
      process.nextTick(() => { process.exit(1) })
    }).end()
  })
  return require(obj.jsonFile)
}

module.exports = fetchJson
