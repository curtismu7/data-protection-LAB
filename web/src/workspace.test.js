import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { forgetWorkspace, renewWorkspace, usableWorkspaceId, workspaceFetch, workspaceId } from "./workspace";

const realFetch = globalThis.fetch;
beforeEach(() => { forgetWorkspace(); window.sessionStorage.clear(); });
afterEach(() => { globalThis.fetch = realFetch; });

describe("workspace id", () => {
  it("is generated as w- plus 16 hex digits, always holds a letter, and is kept in this app's own storage key", () => {
    const id = workspaceId();
    expect(id).toMatch(/^w-[0-9a-f]{16}$/);
    expect(id).toMatch(/[a-z]/);
    expect(window.sessionStorage.getItem("dp.workspace")).toBe(id);
    expect(workspaceId()).toBe(id);
  });
  it("still contains a letter when the random bytes are all digits when written in hex", () => {
    const real = window.crypto.getRandomValues.bind(window.crypto);
    window.crypto.getRandomValues = (a) => { a.fill(0x11); return a; };
    try { expect(workspaceId()).toBe("w-1111111111111111"); } finally { window.crypto.getRandomValues = real; }
  });
  it("accepts and refuses the same ids the server does", () => {
    for (const ok of ["default", "w-0123456789abcdef", "a", "x".repeat(40), "my-tab-1", "abcdefabcdefabcdefabcde"]) expect(usableWorkspaceId(ok), ok).toBe(true);
    for (const bad of ["", "x".repeat(41), "0123456789abcdef01234567", "abcdefabcdefabcdefabcdef", "a".repeat(23) + "1a1", "sk-abcdefghij", "pw-hunter2xyz", "Token-1", "UPPER", "has space", "12345", "ghp_abc"]) expect(usableWorkspaceId(bad), bad).toBe(false);
  });
  it("a stored id the server would refuse is replaced before the first call", () => {
    window.sessionStorage.setItem("dp.workspace", "sk-abcdefghijklmnop1234");
    const id = workspaceId();
    expect(id).toMatch(/^w-[0-9a-f]{16}$/);
    expect(window.sessionStorage.getItem("dp.workspace")).toBe(id);
  });
  it("renewWorkspace picks a different id and stores it", () => {
    const a = workspaceId(); const b = renewWorkspace();
    expect(b).not.toBe(a);
    expect(window.sessionStorage.getItem("dp.workspace")).toBe(b);
  });
});

describe("workspaceFetch", () => {
  const reply = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  it("on 400 bad_workspace renews the id and retries ONCE with the new id", async () => {
    window.sessionStorage.setItem("dp.workspace", "stored-by-an-older-build"); // looks fine to the client, the server says no
    const sent = [];
    globalThis.fetch = async (_u, init) => { sent.push(init.headers["x-workspace"]); return sent.length === 1 ? reply(400, { error: "bad_workspace" }) : reply(200, { ok: true }); };
    const r = await workspaceFetch("/api/rules", { method: "GET" });
    expect(r.status).toBe(200);
    expect(sent).toHaveLength(2);
    expect(sent[0]).toBe("stored-by-an-older-build");
    expect(sent[1]).toMatch(/^w-[0-9a-f]{16}$/);
    expect(window.sessionStorage.getItem("dp.workspace")).toBe(sent[1]);
  });
  it("retries once only: a second bad_workspace is returned as it is", async () => {
    let calls = 0;
    globalThis.fetch = async () => { calls++; return reply(400, { error: "bad_workspace" }); };
    const r = await workspaceFetch("/api/rules", { method: "POST", body: "{}" });
    expect(r.status).toBe(400);
    expect(calls).toBe(2);
  });
  it("any other 400, and any other status, is not retried", async () => {
    for (const [status, body] of [[400, { error: "bad_policy" }], [400, "not json"], [500, { error: "x" }], [200, {}]]) {
      let calls = 0;
      globalThis.fetch = async () => { calls++; return typeof body === "string" ? new Response(body, { status }) : reply(status, body); };
      const r = await workspaceFetch("/api/x", { method: "POST", body: "{}" });
      expect(r.status).toBe(status);
      expect(calls).toBe(1);
    }
  });
  it("sends the same body on the retry", async () => {
    const bodies = [];
    globalThis.fetch = async (_u, init) => { bodies.push(init.body); return bodies.length === 1 ? reply(400, { error: "bad_workspace" }) : reply(200, {}); };
    await workspaceFetch("/api/evaluate", { method: "POST", body: '{"a":1}' });
    expect(bodies).toEqual(['{"a":1}', '{"a":1}']);
  });
});
