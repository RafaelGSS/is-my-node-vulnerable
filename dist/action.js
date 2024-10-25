"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@actions/core");
const index_js_1 = require("./index.js");
async function run() {
    // Inputs
    const nodeVersion = (0, core_1.getInput)("node-version", { required: true });
    const platform = (0, core_1.getInput)("platform", { required: false });
    (0, core_1.info)(`Checking Node.js version ${nodeVersion} with platform ${platform}...`);
    const isVulnerable = await (0, index_js_1.isNodeVulnerable)(nodeVersion, platform);
    if (isVulnerable) {
        (0, core_1.setFailed)(`Node.js version ${nodeVersion} is vulnerable. Please upgrade!`);
    }
    else {
        (0, core_1.info)(`Node.js version ${nodeVersion} is OK!`);
    }
}
run();
