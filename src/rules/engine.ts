import type { WafRule, RuleMatch, RuleTarget } from "../types.js";

export class RulesEngine {
  private rules: WafRule[] = [];

  load(rules: WafRule[]): void {
    this.rules = rules.map((r) => ({ ...r, _regex: new RegExp(r.pattern, "i") } as WafRule));
  }

  async evaluate(request: Request): Promise<RuleMatch[]> {
    const targets = await this.extractTargets(request);
    const matches: RuleMatch[] = [];

    for (const rule of this.rules) {
      if (rule.phase !== "request") continue;
      const regex = new RegExp(rule.pattern, "i");

      for (const targetName of rule.target) {
        const value = targets[targetName] ?? "";
        if (!value) continue;

        const match = regex.exec(value);
        if (match) {
          matches.push({
            ruleId: rule.id,
            ruleName: rule.name,
            score: rule.score,
            action: rule.action,
            target: targetName,
            matchedValue: match[0].slice(0, 100),
            tags: rule.tags,
          });
          break; // one match per rule per request
        }
      }
    }

    return matches;
  }

  private async extractTargets(request: Request): Promise<Record<RuleTarget, string>> {
    const url = new URL(request.url);

    let body = "";
    if (["POST", "PUT", "PATCH"].includes(request.method)) {
      try {
        const clone = request.clone();
        body = await clone.text();
        // limit body scan to first 64KB
        body = body.slice(0, 65536);
      } catch {
        // ignore unreadable bodies
      }
    }

    const headerStr = Array.from(request.headers.entries())
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");

    const decodeParam = (s: string) => {
      try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch { return s; }
    };

    return {
      query: decodeParam(url.search),
      path: decodeParam(url.pathname),
      body,
      headers: headerStr,
    };
  }

  resolveAction(matches: RuleMatch[]): { action: "block" | "challenge" | "log" | "allow"; totalScore: number } {
    if (matches.length === 0) return { action: "allow", totalScore: 0 };

    const totalScore = matches.reduce((sum, m) => sum + m.score, 0);

    // Highest-severity action wins
    const hasBlock = matches.some((m) => m.action === "block");
    const hasChallenge = matches.some((m) => m.action === "challenge");

    if (hasBlock || totalScore >= 100) return { action: "block", totalScore };
    if (hasChallenge || totalScore >= 60) return { action: "challenge", totalScore };
    return { action: "log", totalScore };
  }
}
