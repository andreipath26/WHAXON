#!/usr/bin/env node
"use strict";

// Compile only the Findings page's checked-in Tailwind configuration.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { execFileSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const template = path.join(root, "src/whaxon/interfaces/web/templates/ui_v2_findings.html");
const output = path.join(root, "src/whaxon/interfaces/web/static/findings-v2.css");
const html = fs.readFileSync(template, "utf8");
const match = html.match(/<script id="tailwind-config"[^>]*>([\s\S]*?)<\/script>/);
if (!match) throw new Error("Findings Tailwind config not found");

const sandbox = { tailwind: {} };
vm.runInNewContext(match[1], sandbox, { timeout: 1000 });
const config = sandbox.tailwind.config;
if (!config?.theme?.extend) throw new Error("Unexpected or empty Findings Tailwind config");
config.content = [template];

const temp = fs.mkdtempSync(path.join(os.tmpdir(), "whaxon-findings-css-"));
try {
  const configPath = path.join(temp, "tailwind.config.cjs");
  const inputPath = path.join(temp, "input.css");
  fs.writeFileSync(configPath, "module.exports = " + JSON.stringify(config) + ";\n");
  fs.writeFileSync(inputPath, "@tailwind base;\n@tailwind components;\n@tailwind utilities;\n");
  execFileSync(path.join(root, "node_modules/.bin/tailwindcss"), [
    "--config", configPath, "--input", inputPath, "--output", output, "--minify",
  ], { cwd: root, stdio: "inherit", timeout: 120000 });
  if (fs.statSync(output).size < 10000) throw new Error("Generated Findings CSS is unexpectedly small");
  process.stdout.write("Bundled Findings stylesheet: " + fs.statSync(output).size + " bytes\n");
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
