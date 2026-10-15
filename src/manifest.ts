import { TOOLS } from "./tools";
import { VERSION } from "./version";

export const lobehubManifest = {
  identifier: "paycheck",
  name: "PayCheck",
  version: VERSION,
  author: "Toolweather",
  description:
    "Deterministic trust score for a payee before an agent sends money. check_merchant scores a domain, https URL, or 0x wallet as trusted, unknown, suspicious, or block. It does not send payments or hold wallet keys. Free tier: 100 anonymous checks per UTC day, 1,000 with a pc_live_ key. Over-cap checks are $0.001 USDC on Base via x402. Part of the Toolweather suite.",
  category: "finance",
  tags: ["payments", "trust", "merchant", "x402", "mcp", "toolweather", "security", "wallet"],
  license: "MIT",
  tools: TOOLS.map((tool) => ({
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema,
    annotations: tool.annotations,
  })),
  prompts: [],
  resources: [],
};
