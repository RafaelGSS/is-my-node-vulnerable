function debug (msg) {
  if (process.env.DEBUG) {
    console.debug(msg)
  }
}

module.exports = debug
