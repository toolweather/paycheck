import { writeFileSync } from "node:fs";
import { lobehubManifest } from "../src/manifest.ts";

writeFileSync("lhm.plugin.json", `${JSON.stringify(lobehubManifest, null, 2)}\n`);
console.log("Wrote lhm.plugin.json");
