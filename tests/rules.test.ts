import { describe, it, expect, beforeEach } from "vitest";
import { RulesEngine } from "../src/rules/engine.js";
import owaspRules from "../rules/owasp-core.json";
import type { WafRule } from "../src/types.js";

function makeRequest(url: string, opts: RequestInit = {}): Request {
  return new Request(url, opts);
}

describe("RulesEngine", () => {
  let engine: RulesEngine;

  beforeEach(() => {
    engine = new RulesEngine();
    engine.load(owaspRules as WafRule[]);
  });

  describe("SQL Injection detection", () => {
    it("detects UNION SELECT in query string", async () => {
      const req = makeRequest("https://example.com/search?q=1+UNION+SELECT+*+FROM+users");
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "sqli-001")).toBe(true);
    });

    it("detects DROP TABLE in body", async () => {
      const req = makeRequest("https://example.com/api", {
        method: "POST",
        body: "data=DROP TABLE users",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "sqli-003")).toBe(true);
    });

    it("allows clean queries", async () => {
      const req = makeRequest("https://example.com/search?q=hello+world");
      const matches = await engine.evaluate(req);
      expect(matches.filter((m) => m.tags.includes("sqli"))).toHaveLength(0);
    });
  });

  describe("XSS detection", () => {
    it("detects script tag in query", async () => {
      const req = makeRequest("https://example.com/page?name=<script>alert(1)</script>");
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "xss-001")).toBe(true);
    });

    it("detects event handler injection", async () => {
      const req = makeRequest("https://example.com/page?img=<img+onerror=alert(1)>");
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "xss-002")).toBe(true);
    });

    it("detects javascript protocol", async () => {
      const req = makeRequest("https://example.com/redirect?url=javascript:alert(1)");
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "xss-003")).toBe(true);
    });
  });

  describe("Path Traversal detection", () => {
    it("detects ../", async () => {
      const req = makeRequest("https://example.com/files?path=../../etc/passwd");
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "traversal-001")).toBe(true);
    });

    it("detects URL-encoded traversal", async () => {
      const req = makeRequest("https://example.com/files?path=%2e%2e%2fetc%2fpasswd");
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "traversal-001")).toBe(true);
    });
  });

  describe("Command Injection detection", () => {
    it("detects shell command injection", async () => {
      const req = makeRequest("https://example.com/ping", {
        method: "POST",
        body: "host=127.0.0.1; cat /etc/passwd",
      });
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "cmd-001")).toBe(true);
    });
  });

  describe("SSRF detection", () => {
    it("detects metadata endpoint access", async () => {
      const req = makeRequest("https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/");
      const matches = await engine.evaluate(req);
      expect(matches.some((m) => m.ruleId === "ssrf-001")).toBe(true);
    });
  });

  describe("resolveAction", () => {
    it("returns allow for no matches", () => {
      const result = engine.resolveAction([]);
      expect(result.action).toBe("allow");
      expect(result.totalScore).toBe(0);
    });

    it("returns block when any match has block action", () => {
      const result = engine.resolveAction([
        { ruleId: "sqli-001", ruleName: "SQL Injection", score: 70, action: "block", target: "query", matchedValue: "union select", tags: ["sqli"] },
      ]);
      expect(result.action).toBe("block");
    });

    it("returns block when total score >= 100", () => {
      const result = engine.resolveAction([
        { ruleId: "a", ruleName: "A", score: 55, action: "log", target: "query", matchedValue: "x", tags: [] },
        { ruleId: "b", ruleName: "B", score: 55, action: "log", target: "body", matchedValue: "y", tags: [] },
      ]);
      expect(result.action).toBe("block");
      expect(result.totalScore).toBe(110);
    });
  });
});
