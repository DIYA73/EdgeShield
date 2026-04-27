import type { BotSignals } from "../types.js";

const KNOWN_CRAWLERS = /(?:googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|sogou|exabot|facebot|ia_archiver)/i;

const KNOWN_SCANNERS = /(?:nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|burpsuite|acunetix|nessus|openvas|python-requests\/|go-http-client\/|libwww-perl\/)/i;

const HEADLESS_SIGNALS = /(?:headlesschrome|phantomjs|selenium|webdriver|htmlunit)/i;

// Cloudflare ASN ranges known to be datacenter/hosting providers
const DATACENTER_ASNS = new Set([
  "AS13335", // Cloudflare
  "AS16509", // Amazon AWS
  "AS15169", // Google Cloud
  "AS8075",  // Microsoft Azure
  "AS14061", // DigitalOcean
  "AS63949", // Linode
  "AS20473", // Vultr
  "AS16276", // OVH
  "AS24940", // Hetzner
]);

// Headers a real browser always sends
const EXPECTED_BROWSER_HEADERS = ["accept", "accept-language", "accept-encoding"];

export function analyzeBotSignals(request: Request, cf?: IncomingRequestCfProperties): BotSignals {
  const ua = request.headers.get("user-agent") ?? "";
  const asn = cf?.asn ? `AS${cf.asn}` : "";

  const missingBrowserHeaders = EXPECTED_BROWSER_HEADERS.filter(
    (h) => !request.headers.has(h)
  );

  // UA score: 0 = clearly bot, 1 = clearly human
  let uaScore = 1.0;
  if (!ua) uaScore = 0.0;
  else if (KNOWN_SCANNERS.test(ua)) uaScore = 0.1;
  else if (HEADLESS_SIGNALS.test(ua)) uaScore = 0.2;
  else if (KNOWN_CRAWLERS.test(ua)) uaScore = 0.5;
  else if (missingBrowserHeaders.length >= 2) uaScore = 0.4;
  else if (missingBrowserHeaders.length === 1) uaScore = 0.7;

  return {
    isCrawler: KNOWN_CRAWLERS.test(ua),
    isScanner: KNOWN_SCANNERS.test(ua),
    isHeadless: HEADLESS_SIGNALS.test(ua),
    isDatacenter: DATACENTER_ASNS.has(asn),
    hasAnomalousHeaders: missingBrowserHeaders.length > 0,
    uaScore,
  };
}

export function botScore(signals: BotSignals): number {
  // Returns 0–1 where 1 = definitely bot
  let score = 1 - signals.uaScore;
  if (signals.isScanner) score = Math.max(score, 0.85);
  if (signals.isHeadless) score = Math.max(score, 0.75);
  if (signals.isDatacenter && !signals.isCrawler) score = Math.max(score, 0.5);
  if (signals.hasAnomalousHeaders) score = Math.min(score + 0.15, 1.0);
  return score;
}
