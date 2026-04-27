export interface Env {
  ASSETS: Fetcher;
  WAF_RULES: KVNamespace;
  RATE_LIMITER: DurableObjectNamespace;
  THREAT_EVENTS: DurableObjectNamespace;
  THREAT_SCORE_BLOCK_THRESHOLD: string;
  THREAT_SCORE_CHALLENGE_THRESHOLD: string;
  RATE_LIMIT_WINDOW_SECONDS: string;
  RATE_LIMIT_MAX_REQUESTS: string;
  ADMIN_API_KEY: string;
}

export type RuleAction = "block" | "challenge" | "log" | "allow";
export type RulePhase = "request" | "response";
export type RuleTarget = "query" | "body" | "path" | "headers";

export interface WafRule {
  id: string;
  name: string;
  phase: RulePhase;
  target: RuleTarget[];
  pattern: string;
  score: number;
  action: RuleAction;
  tags: string[];
}

export interface RuleMatch {
  ruleId: string;
  ruleName: string;
  score: number;
  action: RuleAction;
  target: string;
  matchedValue: string;
  tags: string[];
}

export interface BotSignals {
  isCrawler: boolean;
  isScanner: boolean;
  isHeadless: boolean;
  isDatacenter: boolean;
  hasAnomalousHeaders: boolean;
  uaScore: number;
}

export interface ThreatContext {
  ip: string;
  country: string;
  userAgent: string;
  path: string;
  method: string;
  timestamp: number;
  ruleMatches: RuleMatch[];
  botSignals: BotSignals;
  mlScore: number;
  totalScore: number;
  decision: RuleAction;
  requestId: string;
}

export interface ThreatEvent {
  requestId: string;
  ip: string;
  country: string;
  lat: number;
  lon: number;
  attackType: string;
  score: number;
  decision: RuleAction;
  timestamp: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
}
