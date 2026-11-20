#!/usr/bin/env node
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const root = path.resolve(__dirname, "..");
const dest = path.join(root, "src/whaxon/interfaces/web/static");
const sources = JSON.parse(fs.readFileSync(path.join(__dirname, "dashboard-assets-sources.json"), "utf8"));
const allowed = new Set(["fonts.googleapis.com", "fonts.gstatic.com", "lh3.googleusercontent.com", "raw.githubusercontent.com"]);
const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
async function download(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || !allowed.has(parsed.hostname)) throw Error("Disallowed asset source: " + url);
  const res = await fetch(url, { headers: {"User-Agent": ua}, signal: AbortSignal.timeout(25000) });
  if (!res.ok) throw Error("Download " + parsed.hostname + " returned HTTP " + res.status);
  const data = Buffer.from(await res.arrayBuffer());
  if (!data.length || data.length > 12000000) throw Error("Unexpected asset size from " + parsed.hostname);
  return {data,contentType:res.headers.get("content-type")||""};
}
const digest = data => crypto.createHash("sha256").update(data).digest("hex");

async function main() {
  fs.mkdirSync(path.join(dest, "dashboard-fonts"), {recursive:true});
  fs.mkdirSync(path.join(dest, "dashboard-licenses"), {recursive:true});
  let allCss = "/* Bundled, separately licensed typefaces from Google's font catalog. */\n";
  const downloaded = new Map();
  const records = [];
  for (const source of sources.fonts_css) {
    const res = await download(source);
    let css = res.data.toString("utf8");
    const refs = [...css.matchAll(/url\((https:\/\/fonts\.gstatic\.com\/[^)]+)\)/g)].map(x=>x[1]);
    if (!refs.length || !css.includes("@font-face")) throw Error("Unexpected Google Fonts CSS response");
    for (const url of [...new Set(refs)]) {
      if (!downloaded.has(url)) {
        const file = digest(url).slice(0,20) + ".woff2";
        const font = await download(url);
        fs.writeFileSync(path.join(dest,"dashboard-fonts",file),font.data);
        downloaded.set(url,file);
        records.push({file, sha256:digest(font.data),source:url});
      }
      css = css.split(url).join("/static/dashboard-fonts/"+downloaded.get(url));
    }
    allCss += css + "\n";
  }
  fs.writeFileSync(path.join(dest,"dashboard-fonts.css"),allCss);
  for(const image of sources.images) {
    const asset = await download(image.url);
    const ext = asset.contentType.includes("png")?".png":asset.contentType.includes("webp")?".webp":".jpg";
    const file = "dashboard-"+image.name+ext;
    fs.writeFileSync(path.join(dest,file),asset.data);
    records.push({file,sha256:digest(asset.data),source:image.url});
  }
  for(const license of sources.licenses){
    const data=await download(license.url);
    fs.writeFileSync(path.join(dest,"dashboard-licenses",license.name+".txt"),data.data);
  }
  fs.writeFileSync(path.join(dest,"dashboard-assets-manifest.json"),
    JSON.stringify({generatedFrom:"scripts/dashboard-assets-sources.json",files:records},null,2)+"\n");
  process.stdout.write("Bundled "+downloaded.size+" font binaries and "+sources.images.length+" reference images.\n");
}
main().catch(err=>{process.stderr.write(String(err.stack||err)+"\n");process.exitCode=1});
