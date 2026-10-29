// Local-only writer: one fixed daily briefing path, no service credentials.
import { mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { ROOT, today, serve } from "./briefing-lib.mjs";

serve("briefing-writer", [{
  name: "save_briefing",
  description: "Save today's daily briefing markdown atomically in the briefing store.",
  inputSchema: {
    type: "object", additionalProperties: false,
    properties: { markdown: { type: "string", maxLength: 1048576 } },
    required: ["markdown"],
  },
  run: async (args) => {
    if (Object.keys(args).some((key) => key !== "markdown") ||
        typeof args.markdown !== "string" || Buffer.byteLength(args.markdown) > 1048576)
      throw new Error("Expected markdown of at most 1 MiB");
    const dir = join(ROOT, today().day);
    mkdirSync(dir, { recursive: true });
    const file = join(dir, "briefing.md"), temp = join(dir, `.briefing-${randomUUID()}.tmp`);
    try {
      writeFileSync(temp, args.markdown, { flag: "wx", mode: 0o600 });
      renameSync(temp, file);
    } finally {
      try { unlinkSync(temp); } catch {}
    }
    return { file };
  },
}]);
