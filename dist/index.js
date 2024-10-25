#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.isNodeVulnerable = isNodeVulnerable;
exports.main = main;
exports.loadETag = loadETag;
const undici_1 = require("undici");
const node_events_1 = __importDefault(require("node:events"));
const promises_1 = __importDefault(require("node:fs/promises"));
const node_path_1 = __importDefault(require("node:path"));
const debug_1 = __importDefault(require("debug"));
const debug = (0, debug_1.default)("is-my-node-vulnerable");
const satisfies_1 = __importDefault(require("semver/functions/satisfies"));
const ascii_js_1 = require("./ascii.js");
const nv_1 = __importDefault(require("@pkgjs/nv"));
const node_fs_1 = require("node:fs");
(0, undici_1.setGlobalDispatcher)(new undici_1.Agent({ connections: 20 }));
const CORE_RAW_URL = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json";
let lastETagValue;
const coreLocalFile = node_path_1.default.join(__dirname, "core.json");
const ETagFile = node_path_1.default.join(__dirname, ".etag");
async function readLocal(file) {
    const str = await promises_1.default.readFile(file, { encoding: "utf-8" });
    const obj = JSON.parse(str);
    return obj;
}
async function loadETag() {
    if ((0, node_fs_1.existsSync)(ETagFile)) {
        debug("Loading local ETag");
        lastETagValue = (await promises_1.default.readFile(ETagFile)).toString();
    }
}
async function updateLastETag(etag) {
    lastETagValue = etag;
    await promises_1.default.writeFile(ETagFile, lastETagValue);
}
async function fetchCoreIndex() {
    const abortRequest = new node_events_1.default();
    await (0, undici_1.stream)(CORE_RAW_URL, { signal: abortRequest, method: "GET" }, ({ statusCode }) => {
        if (statusCode !== 200) {
            console.error("Request to Github failed. Aborting...");
            abortRequest.emit("abort");
            process.nextTick(() => {
                process.exit(1);
            });
        }
        const ws = (0, node_fs_1.createWriteStream)(coreLocalFile, { flags: "w", autoClose: true });
        return ws;
    });
    return readLocal(coreLocalFile);
}
async function getCoreIndex() {
    const { headers } = await (0, undici_1.request)(CORE_RAW_URL, { method: "HEAD" });
    if (!lastETagValue || lastETagValue !== headers.etag || !(0, node_fs_1.existsSync)(coreLocalFile)) {
        updateLastETag(headers.etag);
        debug("Creating local core.json");
        return (await fetchCoreIndex());
    }
    debug(`No updates from upstream. Getting a cached version: ${coreLocalFile}`);
    return (await readLocal(coreLocalFile));
}
const checkPlatform = (platform) => {
    const availablePlatforms = ["aix", "darwin", "freebsd", "linux", "openbsd", "sunos", "win32", "android"];
    if (platform && !availablePlatforms.includes(platform)) {
        throw new Error(`platform ${platform} is not valid. Please use ${availablePlatforms.join(",")}.`);
    }
};
const isSystemAffected = (platform, affectedEnvironments) => {
    // No platform specified (legacy mode)
    if (!platform || !Array.isArray(affectedEnvironments)) {
        return true;
    }
    // If the environment is matching or all the environments are affected
    if (affectedEnvironments.includes(platform) || affectedEnvironments.includes("all")) {
        return true;
    }
    // Default to false
    return false;
};
function getVulnerabilityList(currentVersion, data, platform) {
    const list = [];
    for (const key in data) {
        const vuln = data[key];
        if ((0, satisfies_1.default)(currentVersion, vuln.vulnerable) &&
            !(0, satisfies_1.default)(currentVersion, vuln.patched) &&
            isSystemAffected(platform, vuln.affectedEnvironments)) {
            const severity = vuln.severity === "unknown" ? "" : `(${vuln.severity})`;
            list.push(`${(0, ascii_js_1.bold)(vuln.cve)}${severity}: ${vuln.overview}\n${(0, ascii_js_1.bold)("Patched versions")}: ${vuln.patched}`);
        }
    }
    return list;
}
async function main(currentVersion, platform) {
    checkPlatform(platform);
    const isEOL = await isNodeEOL(currentVersion);
    if (isEOL) {
        console.error(ascii_js_1.danger);
        console.error(`${currentVersion} is end-of-life. There are high chances of being vulnerable. Please upgrade it.`);
        process.exit(1);
    }
    const coreIndex = await getCoreIndex();
    const list = getVulnerabilityList(currentVersion, coreIndex, platform);
    if (list.length) {
        console.error(ascii_js_1.danger);
        console.error(`${ascii_js_1.vulnerableWarning}\n`);
        console.error(`${list.join(`\n${ascii_js_1.separator}\n\n`)}\n${ascii_js_1.separator}`);
        process.exit(1);
    }
    else {
        console.info(ascii_js_1.allGood);
    }
}
/**
 * @param {string} version
 * @returns {Promise<boolean>} true if the version is end-of-life
 */
async function isNodeEOL(version) {
    const myVersionInfo = await (0, nv_1.default)(version);
    if (!myVersionInfo) {
        // i.e. isNodeEOL('abcd')
        throw Error(`Could not fetch version information for ${version}`);
    }
    if (myVersionInfo.length !== 1) {
        // i.e. isNodeEOL('lts') or isNodeEOL('99')
        throw Error(`Did not get exactly one version record for ${version}`);
    }
    if (!myVersionInfo[0].end) {
        // We got a record, but..
        // v0.12.18 etc does not have an EOL date, which probably means too old.
        return true;
    }
    const now = new Date();
    const end = new Date(myVersionInfo[0].end);
    return now > end;
}
async function isNodeVulnerable(version, platform) {
    checkPlatform(platform);
    const isEOL = await isNodeEOL(version);
    if (isEOL) {
        return true;
    }
    const coreIndex = await getCoreIndex();
    const list = getVulnerabilityList(version, coreIndex, platform);
    return list.length > 0;
}
