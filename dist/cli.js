"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_os_1 = __importDefault(require("node:os"));
const node_process_1 = require("node:process");
const index_js_1 = require("./index.js");
async function cli() {
    if (process.argv[2] !== "-r") {
        await (0, index_js_1.loadETag)();
    }
    await (0, index_js_1.main)(node_process_1.version, node_os_1.default.platform());
}
cli();
