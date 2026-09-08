// tsc only emits compiled JS/declarations; it does not copy non-TS assets
// like the golden-vector JSON fixture. Run after `tsc` so `node --test
// dist/test` can find fixtures relative to the compiled test files, the
// same way `../src/*.js` imports resolve relative to dist/test.
import { cpSync } from "node:fs";
import { fileURLToPath } from "node:url";

const src = fileURLToPath(new URL("../test/fixtures", import.meta.url));
const dest = fileURLToPath(new URL("../dist/test/fixtures", import.meta.url));
cpSync(src, dest, { recursive: true });
