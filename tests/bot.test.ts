import { describe, it, expect } from "vitest";
import { analyzeBotSignals, botScore } from "../src/fingerprint/bot.js";

function makeRequest(ua: string, extraHeaders: Record<string, string> = {}): Request {
  const headers: Record<string, string> = { "user-agent": ua, ...extraHeaders };
  return new Request("https://example.com/", { headers });
}

describe("Bot Fingerprinting", () => {
  it("identifies SQLMap as a scanner", () => {
    const req = makeRequest("sqlmap/1.7.8#stable (https://sqlmap.org)");
    const signals = analyzeBotSignals(req);
    expect(signals.isScanner).toBe(true);
    expect(botScore(signals)).toBeGreaterThan(0.8);
  });

  it("identifies Googlebot as a crawler", () => {
    const req = makeRequest(
      "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
      { accept: "*/*", "accept-language": "en", "accept-encoding": "gzip" }
    );
    const signals = analyzeBotSignals(req);
    expect(signals.isCrawler).toBe(true);
    expect(signals.isScanner).toBe(false);
  });

  it("flags missing browser headers as anomalous", () => {
    const req = makeRequest("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    // No accept, accept-language, accept-encoding headers
    const signals = analyzeBotSignals(req);
    expect(signals.hasAnomalousHeaders).toBe(true);
  });

  it("gives a real browser a low bot score", () => {
    const req = makeRequest(
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      { accept: "text/html,application/xhtml+xml", "accept-language": "en-US,en;q=0.9", "accept-encoding": "gzip, deflate, br" }
    );
    const signals = analyzeBotSignals(req);
    expect(signals.isScanner).toBe(false);
    expect(signals.isHeadless).toBe(false);
    expect(signals.hasAnomalousHeaders).toBe(false);
    expect(botScore(signals)).toBeLessThan(0.3);
  });

  it("flags empty user-agent with maximum bot score", () => {
    const req = makeRequest("");
    const signals = analyzeBotSignals(req);
    expect(botScore(signals)).toBe(1.0);
  });
});
