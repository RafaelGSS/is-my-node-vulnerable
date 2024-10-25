import os from "node:os";
import { version } from "node:process";
import { main, loadETag } from "./index.js";
async function cli() {
	if (process.argv[2] !== "-r") {
		await loadETag();
	}
	await main(version, os.platform());
}
cli();
