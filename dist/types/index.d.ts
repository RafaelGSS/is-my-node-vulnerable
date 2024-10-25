#!/usr/bin/env node
declare function loadETag(): Promise<void>;
declare function main(currentVersion: string, platform: string): Promise<void>;
declare function isNodeVulnerable(version: string, platform?: string): Promise<boolean>;
export { isNodeVulnerable, main, loadETag };
