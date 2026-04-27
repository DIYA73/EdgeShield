import type { Env } from "../types.js";

// ASNs known to be pure hosting/VPS with no residential users
const MALICIOUS_ASNS = new Set([
  "AS209", "AS3223", "AS9009", "AS51167", "AS60781",
  "AS41108", "AS206728", "AS213371", "AS395839", "AS397423",
]);

// CIDR prefix strings for known bad ranges (simplified prefix match)
const BAD_PREFIXES = ["185.220.", "162.247.", "171.25.", "176.10.", "193.218."];

export interface IpReputation {
  score: number;       // 0-1, higher = worse
  isBlocklisted: boolean;
  cfThreatScore: number;
  isMaliciousAsn: boolean;
  isBadPrefix: boolean;
}

export async function getIpReputation(
  ip: string,
  cf: IncomingRequestCfProperties | undefined,
  kv: KVNamespace
): Promise<IpReputation> {
  const [blocklisted, cfScore, asnBad, prefixBad] = await Promise.all([
    kv.get(`blocklist:${ip}`).then((v) => v !== null),
    Promise.resolve(cf?.threatScore ?? 0),
    Promise.resolve(MALICIOUS_ASNS.has(`AS${cf?.asn ?? 0}`)),
    Promise.resolve(BAD_PREFIXES.some((p) => ip.startsWith(p))),
  ]);

  const cfNorm = cfScore / 100;
  let score = cfNorm;
  if (blocklisted) score = 1.0;
  else if (asnBad) score = Math.max(score, 0.6);
  else if (prefixBad) score = Math.max(score, 0.5);

  return {
    score,
    isBlocklisted: blocklisted,
    cfThreatScore: cfScore,
    isMaliciousAsn: asnBad,
    isBadPrefix: prefixBad,
  };
}
