import type { BotSignals, RuleMatch } from "../types.js";

/**
 * Lightweight heuristic threat scorer that mimics what a pre-trained ML model would output.
 * Replace scoreFeatures() with actual ONNX inference when a model is available.
 * Features mirror what a gradient-boosted classifier would use.
 */

interface Features {
  botScore: number;           // 0–1 from fingerprinter
  ruleMatchCount: number;     // number of WAF rule hits
  ruleScoreSum: number;       // total WAF score (normalised to 0–1)
  hasBlockAction: number;     // 1 if any rule says block
  pathDepth: number;          // normalised URL depth (0–1)
  queryParamCount: number;    // normalised (0–1)
  isKnownBadUA: number;       // 1 if scanner UA
  isDatacenter: number;       // 1 if datacenter ASN
}

function extractFeatures(
  botSignals: BotSignals,
  ruleMatches: RuleMatch[],
  url: URL
): Features {
  const queryParams = [...url.searchParams.keys()].length;
  const pathDepth = Math.min(url.pathname.split("/").length - 1, 10) / 10;

  return {
    botScore: 1 - botSignals.uaScore,
    ruleMatchCount: Math.min(ruleMatches.length, 10) / 10,
    ruleScoreSum: Math.min(ruleMatches.reduce((s, r) => s + r.score, 0), 300) / 300,
    hasBlockAction: ruleMatches.some((r) => r.action === "block") ? 1 : 0,
    pathDepth,
    queryParamCount: Math.min(queryParams, 20) / 20,
    isKnownBadUA: botSignals.isScanner || botSignals.isHeadless ? 1 : 0,
    isDatacenter: botSignals.isDatacenter ? 1 : 0,
  };
}

// Simulates a trained model's weight vector (logistic regression style)
const WEIGHTS: Record<keyof Features, number> = {
  botScore: 0.30,
  ruleMatchCount: 0.12,
  ruleScoreSum: 0.28,
  hasBlockAction: 0.15,
  pathDepth: 0.02,
  queryParamCount: 0.04,
  isKnownBadUA: 0.06,
  isDatacenter: 0.03,
};

const BIAS = 0.00;

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

export function mlScore(
  botSignals: BotSignals,
  ruleMatches: RuleMatch[],
  url: URL
): number {
  const features = extractFeatures(botSignals, ruleMatches, url);

  let logit = BIAS;
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    logit += weight * (features[key as keyof Features] ?? 0);
  }

  return sigmoid(logit * 8 - 3);
}
