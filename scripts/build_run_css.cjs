#!/usr/bin/env node
"use strict";
// Compile Run page utilities from its supplied, checked-in Tailwind config.
// Runtime rendering uses only the packaged stylesheet and local font assets.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { execFileSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const template = path.join(root, "src/whaxon/interfaces/web/templates/ui_v2_run.html");
const output = path.join(root, "src/whaxon/interfaces/web/static/run-v2.css");
const html = fs.readFileSync(template, "utf8");
const match = html.match(/<script id="tailwind-config"[^>]*>([\s\S]*?)<\/script>/);
if (!match) throw new Error("Run Tailwind config not found in supplied template");
const sandbox = { tailwind: {} };
vm.runInNewContext(match[1], sandbox, { timeout: 1000 });
const config = sandbox.tailwind.config;
if (!config || !config.theme || !config.theme.extend) {
  throw new Error("Unexpected or empty Run Tailwind config");
}
config.content = [template];
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "whaxon-run-css-"));
try {
  const configPath = path.join(temp, "tailwind.config.cjs");
  const inputPath = path.join(temp, "input.css");
  fs.writeFileSync(configPath, "module.exports = " + JSON.stringify(config) + ";\n");
  fs.writeFileSync(inputPath, "@tailwind base;\n@tailwind components;\n@tailwind utilities;\n");
  fs.mkdirSync(path.dirname(output), { recursive: true });
  execFileSync(path.join(root, "node_modules/.bin/tailwindcss"),
    ["--config", configPath, "--input", inputPath, "--output", output, "--minify"],
    { cwd: root, stdio: "inherit", timeout: 120000 });
  if (fs.statSync(output).size < 10000) throw new Error("Bundled Run CSS is unexpectedly small");
  process.stdout.write("Bundled Run stylesheet: " + fs.statSync(output).size + " bytes\n");
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
