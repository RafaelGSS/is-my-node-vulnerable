# is-my-node-vulnerable

This package helps ensure the security of your Node.js installation by checking for known vulnerabilities.
It compares the version of Node.js you have installed (`process.version`) to the [Node.js Security Database][]
and alerts you if a vulnerability is found.

## Usage

```
npx is-my-node-vulnerable
```

It's strongly recommended to include this as a step in the app CI.

### Output - When vulnerable


```console
$ node -v
v19.0.0
$ npx is-my-node-vulnerable


██████   █████  ███    ██  ██████  ███████ ██████
██   ██ ██   ██ ████   ██ ██       ██      ██   ██
██   ██ ███████ ██ ██  ██ ██   ███ █████   ██████
██   ██ ██   ██ ██  ██ ██ ██    ██ ██      ██   ██
██████  ██   ██ ██   ████  ██████  ███████ ██   ██


The current Node.js version (v19.0.0) is vulnerable to the following CVEs:

CVE-2022-43548: The Node.js rebinding protector for --inspect still allows invalid IP address, specifically, the octal format.
Patched versions: ^14.21.1 || ^16.18.1 || ^18.12.1 || ^19.0.1
=============================================================================================================================================
```

### Output - When non-vulnerable

```console
$ node -v
v19.5.0
$ npx is-my-node-vulnerable


 █████  ██      ██           ██████   ██████   ██████  ██████         ██
██   ██ ██      ██          ██       ██    ██ ██    ██ ██   ██     ██  ██
███████ ██      ██          ██   ███ ██    ██ ██    ██ ██   ██         ██
██   ██ ██      ██          ██    ██ ██    ██ ██    ██ ██   ██     ██  ██
██   ██ ███████ ███████      ██████   ██████   ██████  ██████         ██

```

## API

This package also exports a function `isNodeVulnerable` to perform the check in runtime

```js
const { isNodeVulnerable } = require('is-my-node-vulnerable')

isNodeVulnerable('19.0.0') // true
```

[Node.js Security Database]: https://github.com/nodejs/security-wg/tree/main/vuln
