import { rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
for (const output of ["dist", "server.js"]) {
  rmSync(resolve(projectRoot, output), { recursive: true, force: true });
}