import { describe, expect, it } from "vitest";
import { encodeFrame, pushFrames } from "../src/stdio";

describe("stdio framing", () => {
  it("round-trips a JSON-RPC message with Content-Length", () => {
    const message = { jsonrpc: "2.0", id: 1, method: "tools/list" };
    const frame = encodeFrame(message);
    const parsed = pushFrames(new Uint8Array(), frame);
    expect(parsed.messages).toEqual([message]);
    expect(parsed.rest.length).toBe(0);
  });

  it("waits for a partial body", () => {
    const frame = encodeFrame({ jsonrpc: "2.0", id: 2, method: "ping" });
    const partial = pushFrames(new Uint8Array(), frame.slice(0, 20));
    expect(partial.messages).toEqual([]);
    const rest = pushFrames(partial.rest, frame.slice(20));
    expect(rest.messages).toEqual([{ jsonrpc: "2.0", id: 2, method: "ping" }]);
  });
});
