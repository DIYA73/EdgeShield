import type { BotSignals, RuleMatch } from "../types.js";

/**
 * MLP threat scorer with hot-swappable weights.
 *
 * Weight loading priority:
 *   1. In-memory cache (reset on Worker cold start)
 *   2. KV key "model:mlp-v1" (upload via scripts/train_model.py)
 *   3. Bundled fallback weights below
 *
 * To update the model without redeployment:
 *   python scripts/train_model.py
 *   npx wrangler kv key put --remote "model:mlp-v1" --path=model/weights.json \
 *     --namespace-id=c9d04c1148d246e3a6f1a2038c7fca92
 */

interface ModelWeights {
  W: number[][][];  // [layer][neuron][weight]
  b: number[][];    // [layer][neuron]
}

// Bundled fallback — mirrors model/weights.json
const FALLBACK_WEIGHTS: ModelWeights = {
  W: [
    [
      [0.00, 0.00, 2.00, 2.50, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00],
      [2.00, 0.00, 0.00, 0.00, 0.00, 0.00, 1.50, 1.00, 1.00, 0.00, 0.00, 0.00],
      [0.00, 0.00, 0.00, 0.00, 2.00, 2.00, 0.00, 0.50, 0.00, 0.00, 0.00, 0.00],
      [1.00, 0.00, 0.00, 0.00, 0.00, 0.00, 2.00, 0.00, 1.50, 0.00, 0.00, 0.00],
    ],
    [[0.65, 0.35, 0.60, 0.35]],
  ],
  b: [[-0.50, -1.00, -0.50, -0.50], [-3.00]],
};

// Per-isolate cache — survives warm requests, cleared on cold start
let cachedWeights: ModelWeights | null = null;

export async function loadWeights(kv: KVNamespace): Promise<void> {
  if (cachedWeights) return;
  try {
    const raw = await kv.get("model:mlp-v1");
    if (raw) {
      const parsed = JSON.parse(raw);
      // Normalise: scikit-learn exports coefs_ as (n_in × n_out), transpose to (n_out × n_in)
      cachedWeights = {
        W: parsed.W,
        b: parsed.b,
      };
      return;
    }
  } catch {
    // Fall through to bundled weights
  }
  cachedWeights = FALLBACK_WEIGHTS;
}

function relu(x: number): number { return x > 0 ? x : 0; }
function sigmoid(x: number): number { return 1 / (1 + Math.exp(-x)); }

function forward(features: number[], weights: ModelWeights): number {
  const { W, b } = weights;

  // Hidden layers (all but last use ReLU)
  let activation: number[] = features;
  for (let l = 0; l < W.length - 1; l++) {
    const layer = W[l]!;
    const bias = b[l]!;
    activation = layer.map((neuronWeights, i) => {
      const z = neuronWeights.reduce((s, w, j) => s + w * (activation[j] ?? 0), bias[i] ?? 0);
      return relu(z);
    });
  }

  // Output layer — single sigmoid neuron
  const outWeights = W[W.length - 1]![0]!;
  const outBias = b[b.length - 1]![0] ?? 0;
  const logit = outWeights.reduce((s, w, j) => s + w * (activation[j] ?? 0), outBias);
  return sigmoid(logit);
}

const METHOD_RISK: Record<string, number> = { DELETE: 0.7, PUT: 0.3, POST: 0.3, PATCH: 0.2, GET: 0.0 };

export function mlScore(
  botSignals: BotSignals,
  ruleMatches: RuleMatch[],
  url: URL,
  ipRepScore = 0,
  cfThreatScore = 0,
  method = "GET"
): number {
  const features = [
    1 - botSignals.uaScore,
    Math.min(ruleMatches.length, 10) / 10,
    Math.min(ruleMatches.reduce((s, r) => s + r.score, 0), 300) / 300,
    ruleMatches.some((r) => r.action === "block") ? 1 : 0,
    ipRepScore,
    cfThreatScore / 100,
    botSignals.isScanner || botSignals.isHeadless ? 1 : 0,
    botSignals.isDatacenter ? 1 : 0,
    botSignals.hasAnomalousHeaders ? 1 : 0,
    Math.min(url.pathname.split("/").length - 1, 10) / 10,
    Math.min([...url.searchParams.keys()].length, 20) / 20,
    METHOD_RISK[method.toUpperCase()] ?? 0,
  ];

  return forward(features, cachedWeights ?? FALLBACK_WEIGHTS);
}
