"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_assert_1 = __importDefault(require("node:assert"));
const nv_1 = __importDefault(require("@pkgjs/nv"));
const index_js_1 = require("./index.js");
async function test() {
    // of course, this test is fragile
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("20.5.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("20.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("19.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("18.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("14.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("16.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("19.6.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("18.14.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("16.19.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("20.8.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("20.11.0"));
    const activeVersions = await (0, nv_1.default)("active");
    for (const active of activeVersions) {
        node_assert_1.default.ok(!(await (0, index_js_1.isNodeVulnerable)(active.version)));
    }
    const ltsVersions = await (0, nv_1.default)(["lts"]);
    if (ltsVersions.length > 1) {
        node_assert_1.default.rejects(() => (0, index_js_1.isNodeVulnerable)("lts"), /not get exactly one version/);
    }
    node_assert_1.default.rejects(() => (0, index_js_1.isNodeVulnerable)("999"), /not get exactly one version/);
    node_assert_1.default.rejects(() => (0, index_js_1.isNodeVulnerable)("Unobtanium"), /not get exactly one version/); // i.e. not found
    node_assert_1.default.rejects(() => (0, index_js_1.isNodeVulnerable)("24.0.0"), /not get exactly one version/);
    // EOL
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("19.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("16.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("17.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("15.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("13.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("12.0.0"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("v0.12.18"));
    // Platform specific
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("22.4.0", "win32"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("19.0.0", "linux"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("18.0.0", "win32"));
    node_assert_1.default.ok(await (0, index_js_1.isNodeVulnerable)("14.0.0", "android"));
    node_assert_1.default.rejects(() => (0, index_js_1.isNodeVulnerable)("20.0.0", "non-valid-platform"), /platform non-valid-platform is not valid. Please use aix,darwin,freebsd,linux,openbsd,sunos,win32,android/);
}
test();
