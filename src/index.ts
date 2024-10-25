#!/usr/bin/env node

import { request, stream, setGlobalDispatcher, Agent } from "undici";
import EE from "node:events";
import fs from "node:fs/promises";
import path from "node:path";
import debugModule from "debug";
const debug = debugModule("is-my-node-vulnerable");
import satisfies from "semver/functions/satisfies";
import { danger, vulnerableWarning, bold, separator, allGood } from "./ascii.js";
import nv from "@pkgjs/nv";
import { createWriteStream, existsSync, type WriteStream } from "node:fs";
import type { corejson } from "src/types/core.json.js";

setGlobalDispatcher(new Agent({ connections: 20 }));

const CORE_RAW_URL = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json";

let lastETagValue: string | NodeJS.ArrayBufferView | undefined;

const coreLocalFile = path.join(__dirname, "core.json");
const ETagFile = path.join(__dirname, ".etag");
async function readLocal(file: string) {
	const str = await fs.readFile(file, { encoding: "utf-8" });
	const obj = JSON.parse(str);
	return obj as corejson;
}

async function loadETag() {
	if (existsSync(ETagFile)) {
		debug("Loading local ETag");
		lastETagValue = (await fs.readFile(ETagFile)).toString();
	}
}

async function updateLastETag(etag: string) {
	lastETagValue = etag;
	await fs.writeFile(ETagFile, lastETagValue);
}

async function fetchCoreIndex(): Promise<WriteStream | corejson> {
	const abortRequest = new EE();
	await stream(CORE_RAW_URL, { signal: abortRequest, method: "GET" }, ({ statusCode }) => {
		if (statusCode !== 200) {
			console.error("Request to Github failed. Aborting...");
			abortRequest.emit("abort");
			process.nextTick(() => {
				process.exit(1);
			});
		}
		const ws = createWriteStream(coreLocalFile, { flags: "w", autoClose: true });
		return ws;
	});
	return readLocal(coreLocalFile);
}

async function getCoreIndex() {
	const { headers } = await request(CORE_RAW_URL, { method: "HEAD" });
	if (!lastETagValue || lastETagValue !== headers.etag || !existsSync(coreLocalFile)) {
		updateLastETag(headers.etag as string);
		debug("Creating local core.json");
		return (await fetchCoreIndex()) as corejson;
	}
	debug(`No updates from upstream. Getting a cached version: ${coreLocalFile}`);
	return (await readLocal(coreLocalFile)) as corejson;
}

const checkPlatform = (platform?: string) => {
	const availablePlatforms = ["aix", "darwin", "freebsd", "linux", "openbsd", "sunos", "win32", "android"];
	if (platform && !availablePlatforms.includes(platform)) {
		throw new Error(`platform ${platform} is not valid. Please use ${availablePlatforms.join(",")}.`);
	}
};
const isSystemAffected = (platform?: string, affectedEnvironments?: string | string[]) => {
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

function getVulnerabilityList(currentVersion: string, data: corejson, platform?: string) {
	const list = [];
	for (const key in data) {
		const vuln = data[key];
		if (
			satisfies(currentVersion, vuln.vulnerable) &&
			!satisfies(currentVersion, vuln.patched) &&
			isSystemAffected(platform, vuln.affectedEnvironments)
		) {
			const severity = vuln.severity === "unknown" ? "" : `(${vuln.severity})`;
			list.push(`${bold(vuln.cve)}${severity}: ${vuln.overview}\n${bold("Patched versions")}: ${vuln.patched}`);
		}
	}
	return list;
}

async function main(currentVersion: string, platform: string) {
	checkPlatform(platform);
	const isEOL = await isNodeEOL(currentVersion);
	if (isEOL) {
		console.error(danger);
		console.error(`${currentVersion} is end-of-life. There are high chances of being vulnerable. Please upgrade it.`);
		process.exit(1);
	}

	const coreIndex = await getCoreIndex();
	const list = getVulnerabilityList(currentVersion, coreIndex, platform);
	if (list.length) {
		console.error(danger);
		console.error(`${vulnerableWarning}\n`);
		console.error(`${list.join(`\n${separator}\n\n`)}\n${separator}`);
		process.exit(1);
	} else {
		console.info(allGood);
	}
}

/**
 * @param {string} version
 * @returns {Promise<boolean>} true if the version is end-of-life
 */
async function isNodeEOL(version: string): Promise<boolean> {
	const myVersionInfo = await nv(version);
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

async function isNodeVulnerable(version: string, platform?: string) {
	checkPlatform(platform);
	const isEOL = await isNodeEOL(version);
	if (isEOL) {
		return true;
	}

	const coreIndex = await getCoreIndex();
	const list = getVulnerabilityList(version, coreIndex, platform);
	return list.length > 0;
}

// if (process.argv[2] !== '-r') {
//     loadETag()
// }

export { isNodeVulnerable, main, loadETag };
