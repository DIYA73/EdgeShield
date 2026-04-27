import type { ThreatContext, ThreatEvent } from "../types.js";

// Durable Object that fans out threat events to connected WebSocket clients
export class ThreatEventBus implements DurableObject {
  private state: DurableObjectState;
  private sessions: Set<WebSocket> = new Set();

  constructor(state: DurableObjectState) {
    this.state = state;
    this.state.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/publish") {
      const event: ThreatEvent = await request.json();
      this.broadcast(event);
      return new Response("ok");
    }

    if (url.pathname === "/subscribe" && request.headers.get("Upgrade") === "websocket") {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server);
      this.sessions.add(server);
      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response("Not found", { status: 404 });
  }

  webSocketClose(ws: WebSocket): void {
    this.sessions.delete(ws);
  }

  private broadcast(event: ThreatEvent): void {
    const payload = JSON.stringify(event);
    for (const ws of this.sessions) {
      try {
        ws.send(payload);
      } catch {
        this.sessions.delete(ws);
      }
    }
  }
}

export function buildThreatEvent(ctx: ThreatContext, cf?: IncomingRequestCfProperties): ThreatEvent {
  const topAttackType = ctx.ruleMatches[0]?.tags[0] ?? (ctx.botSignals.isScanner ? "scanner" : "anomaly");

  return {
    requestId: ctx.requestId,
    ip: ctx.ip,
    country: ctx.country,
    lat: (cf?.latitude as number | undefined) ?? 0,
    lon: (cf?.longitude as number | undefined) ?? 0,
    attackType: topAttackType,
    score: ctx.mlScore,
    decision: ctx.decision,
    timestamp: ctx.timestamp,
  };
}

export async function publishThreatEvent(
  namespace: DurableObjectNamespace,
  event: ThreatEvent
): Promise<void> {
  // All threat events go to a single global bus instance
  const id = namespace.idFromName("global");
  const stub = namespace.get(id);
  await stub.fetch("http://internal/publish", {
    method: "POST",
    body: JSON.stringify(event),
    headers: { "Content-Type": "application/json" },
  });
}
