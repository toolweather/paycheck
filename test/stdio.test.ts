import { describe, expect, it } from "vitest";
import { encodeNdjson, takeStdioMessages } from "../src/stdio";

function contentLengthFrame(message: unknown): string {
  const json = JSON.stringify(message);
  const length = new TextEncoder().encode(json).length;
  return `Content-Length: ${length}\r\n\r\n${json}`;
}

describe("stdio framing", () => {
  it("round-trips newline-delimited JSON-RPC", () => {
    const message = { jsonrpc: "2.0", id: 1, method: "tools/list" };
    const line = encodeNdjson(message);
    expect(line.endsWith("\n")).toBe(true);
    expect(line.includes("Content-Length")).toBe(false);
    const parsed = takeStdioMessages(line);
    expect(parsed.messages).toEqual([message]);
    expect(parsed.rest).toBe("");
  });

  it("reads several NDJSON messages and holds a partial line", () => {
    const first = { jsonrpc: "2.0", id: 1, method: "initialize" };
    const second = { jsonrpc: "2.0", method: "notifications/initialized" };
    const partial = takeStdioMessages(
      `${JSON.stringify(first)}\n${JSON.stringify(second)}\n{"jsonrpc":"2.0","id":2,"method":"to`,
    );
    expect(partial.messages).toEqual([first, second]);
    const rest = takeStdioMessages(`${partial.rest}ols/list"}\n`);
    expect(rest.messages).toEqual([{ jsonrpc: "2.0", id: 2, method: "tools/list" }]);
    expect(rest.rest).toBe("");
  });

  it("parses Content-Length frames on input", () => {
    const message = { jsonrpc: "2.0", id: 1, method: "tools/list" };
    const parsed = takeStdioMessages(contentLengthFrame(message));
    expect(parsed.messages).toEqual([message]);
    expect(parsed.rest).toBe("");
  });

  it("waits for a partial Content-Length body", () => {
    const message = { jsonrpc: "2.0", id: 2, method: "ping" };
    const frame = contentLengthFrame(message);
    const headerEnd = frame.indexOf("\r\n\r\n") + 4;
    const mid = headerEnd + 4;
    const partial = takeStdioMessages(frame.slice(0, mid));
    expect(partial.messages).toEqual([]);
    expect(partial.rest).toBe(frame.slice(0, mid));
    const rest = takeStdioMessages(partial.rest + frame.slice(mid));
    expect(rest.messages).toEqual([message]);
    expect(rest.rest).toBe("");
  });

  it("counts Content-Length in UTF-8 bytes", () => {
    const message = { jsonrpc: "2.0", id: 1, method: "ping", params: { note: "é" } };
    const parsed = takeStdioMessages(contentLengthFrame(message));
    expect(parsed.messages).toEqual([message]);
    expect(parsed.rest).toBe("");
  });

  it("reads NDJSON and Content-Length in one buffer and skips non-JSON lines", () => {
    const listed = { jsonrpc: "2.0", id: 2, method: "tools/list" };
    const ping = { jsonrpc: "2.0", id: 1, method: "ping" };
    const mixed = `not json\n\n${JSON.stringify(listed)}\r\n${contentLengthFrame(ping)}`;
    const taken = takeStdioMessages(mixed);
    expect(taken.rest).toBe("");
    expect(taken.messages).toEqual([listed, ping]);
  });
});
