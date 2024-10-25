import { getInput, info, setFailed } from "@actions/core";
import { isNodeVulnerable } from "./index.js";

async function run() {
	// Inputs
	const nodeVersion = getInput("node-version", { required: true });
	const platform = getInput("platform", { required: false });

	info(`Checking Node.js version ${nodeVersion} with platform ${platform}...`);
	const isVulnerable = await isNodeVulnerable(nodeVersion, platform);
	if (isVulnerable) {
		setFailed(`Node.js version ${nodeVersion} is vulnerable. Please upgrade!`);
	} else {
		info(`Node.js version ${nodeVersion} is OK!`);
	}
}

run();
