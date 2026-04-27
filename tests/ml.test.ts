import { describe, it, expect } from "vitest";
import { mlScore } from "../src/ml/scorer.js";
import type { BotSignals, RuleMatch } from "../src/types.js";

const cleanBot: BotSignals = {
  isCrawler: false,
  isScanner: false,
  isHeadless: false,
  isDatacenter: false,
  hasAnomalousHeaders: false,
  uaScore: 1.0,
};

const scannerBot: BotSignals = {
  isCrawler: false,
  isScanner: true,
  isHeadless: true,
  isDatacenter: true,
  hasAnomalousHeaders: true,
  uaScore: 0.1,
};

const sqliMatch: RuleMatch = {
  ruleId: "sqli-001",
  ruleName: "SQL Injection",
  score: 70,
  action: "block",
  target: "query",
  matchedValue: "union select",
  tags: ["sqli"],
};

describe("ML Scorer", () => {
  it("gives clean request a low threat score", () => {
    const url = new URL("https://example.com/home");
    const score = mlScore(cleanBot, [], url);
    expect(score).toBeLessThan(0.3);
  });

  it("gives scanner + SQLi a high threat score", () => {
    const url = new URL("https://example.com/search?q=1+UNION+SELECT+*");
    const score = mlScore(scannerBot, [sqliMatch], url);
    expect(score).toBeGreaterThan(0.8);
  });

  it("score is between 0 and 1", () => {
    const url = new URL("https://example.com/");
    const score = mlScore(scannerBot, [sqliMatch, sqliMatch], url);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(1);
  });

  it("rule matches increase score compared to clean request", () => {
    const url = new URL("https://example.com/page?q=test");
    const withMatch = mlScore(cleanBot, [sqliMatch], url);
    const withoutMatch = mlScore(cleanBot, [], url);
    expect(withMatch).toBeGreaterThan(withoutMatch);
  });
});
