import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { themeCss } from "./css.ts";

/** `npm run theme:css` rewrites the committed variable layer from tokens.ts. */
const target = fileURLToPath(new URL("./tokens.generated.css", import.meta.url));
writeFileSync(target, themeCss());
console.log(`wrote ${target}`);
