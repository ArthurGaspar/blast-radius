// Demo inventory for the browser build: 70 sites. Six are written by hand (the stories in the README); the rest are
// generated from site templates. Versions are never invented: for each product the generator collects the release
// numbers that the vulnerability data itself names (fixed-in versions and range bounds) and picks older or newer ones
// according to each site's patch hygiene. Site colors therefore come from real matching against real releases.

import { catalog, type Engine, productKeys } from "../engine/engine";
import { compareVersions, identityKey } from "../engine/matching";

export const DEMO = { username: "analyst", password: "radar-demo-1" };

type Kind = "office" | "datacenter" | "cloud";
type Hygiene = "tight" | "average" | "lax";

const TEMPLATES: Record<string, { label: string; products: string[] }> = {
  inference: { label: "Inference", products: ["ollama", "vllm", "ray", "nginx"] },
  training: { label: "Training", products: ["pytorch", "ray", "mlflow", "kubernetes"] },
  research: { label: "Research lab", products: ["transformers", "llama-index", "jupyter-server", "langchain"] },
  product: { label: "AI product", products: ["langchain", "gradio", "nginx", "openssl"] },
  office: { label: "Office", products: ["openssh", "nginx"] },
  datacenter: { label: "Data center", products: ["log4j", "openssl", "nginx", "openssh", "kubernetes"] },
  edge: { label: "Edge PoP", products: ["nginx", "openssl"] },
};

// [preset, kind, template, hygiene]
const GENERATED: [string, Kind, keyof typeof TEMPLATES, Hygiene][] = [
  ["us-east-2", "cloud", "training", "average"], ["us-west-1", "cloud", "inference", "lax"], ["oregon", "cloud", "inference", "tight"],
  ["council-bluffs", "cloud", "training", "tight"], ["dallas", "datacenter", "datacenter", "average"], ["new-york", "office", "office", "average"],
  ["chicago", "office", "office", "tight"], ["austin", "office", "product", "lax"], ["seattle", "office", "research", "tight"],
  ["atlanta", "datacenter", "datacenter", "lax"], ["miami", "datacenter", "edge", "average"], ["denver", "datacenter", "edge", "tight"],
  ["montreal", "cloud", "inference", "average"], ["toronto", "office", "product", "average"], ["vancouver", "office", "research", "lax"],
  ["queretaro", "cloud", "edge", "average"], ["mexico-city", "office", "office", "lax"], ["bogota", "office", "product", "average"],
  ["lima", "office", "office", "average"], ["santiago", "datacenter", "edge", "tight"], ["buenos-aires", "office", "research", "average"],
  ["rio", "office", "product", "lax"], ["recife", "datacenter", "edge", "average"], ["london", "office", "product", "tight"],
  ["dublin", "cloud", "inference", "average"], ["paris", "cloud", "training", "average"], ["lisbon", "office", "office", "tight"],
  ["madrid", "cloud", "edge", "average"], ["milan", "cloud", "inference", "lax"], ["zurich", "cloud", "research", "tight"],
  ["amsterdam", "datacenter", "datacenter", "average"], ["berlin", "office", "research", "average"], ["warsaw", "office", "office", "lax"],
  ["stockholm", "cloud", "training", "tight"], ["helsinki", "cloud", "inference", "average"], ["oslo", "datacenter", "edge", "tight"],
  ["vienna", "office", "office", "average"], ["istanbul", "datacenter", "datacenter", "lax"], ["athens", "office", "office", "average"],
  ["tel-aviv", "office", "research", "tight"], ["cairo", "datacenter", "edge", "lax"], ["lagos", "datacenter", "edge", "average"],
  ["nairobi", "office", "office", "average"], ["johannesburg", "datacenter", "datacenter", "average"], ["cape-town", "cloud", "inference", "lax"],
  ["bahrain", "cloud", "edge", "average"], ["dubai", "cloud", "inference", "tight"], ["riyadh", "datacenter", "datacenter", "average"],
  ["mumbai", "cloud", "training", "lax"], ["bengaluru", "office", "research", "average"], ["hyderabad", "cloud", "inference", "average"],
  ["delhi", "office", "product", "lax"], ["jakarta", "cloud", "edge", "average"], ["kuala-lumpur", "cloud", "inference", "average"],
  ["bangkok", "cloud", "edge", "lax"], ["manila", "office", "office", "average"], ["ho-chi-minh", "office", "product", "average"],
  ["hong-kong", "cloud", "inference", "average"], ["taipei", "cloud", "training", "tight"], ["seoul", "office", "research", "tight"],
  ["osaka", "cloud", "edge", "tight"], ["sydney", "cloud", "inference", "average"], ["melbourne", "office", "product", "average"],
  ["auckland", "cloud", "edge", "tight"], ["perth", "datacenter", "datacenter", "lax"], ["reykjavik", "datacenter", "edge", "tight"],
];

// Where in a product's release history each hygiene profile tends to sit (0 = oldest named release, 1 = newest).
const SPOTS: Record<Hygiene, number[]> = {
  tight: [1],
  average: [1, 1, 1, 0.97, 0.92],
  lax: [0.9, 0.8, 0.7, 0.55, 0.4],
};

function mulberry32(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Release numbers each product's vulnerability data names, oldest first: plain dotted versions (and OpenSSH pN). */
export function releasesFromData(vulns: { ranges: any[] }[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const p of catalog.products) {
    const keys = new Set(productKeys(p));
    const found = new Set<string>();
    for (const v of vulns)
      for (const r of v.ranges)
        if (keys.has(identityKey(r)))
          for (const x of [r.fixed, r.endExcluding, r.startIncluding, r.exact])
            if (typeof x === "string" && /^\d+(\.\d+){1,3}(p\d)?$/.test(x) && !/^\d{4}\./.test(x)) found.add(x);
    out.set(p.key, [...found].sort(compareVersions));
  }
  return out;
}

const regionOf = (label: string) => /\(([^)]+)\)/.exec(label)?.[1];
const cityOf = (label: string) => label.replace(/\s*\(.*\)$/, "");

export async function seedDemo(engine: Engine, snapshot: { vulnerabilities: { ranges: any[] }[] }) {
  const call = async (method: string, path: string, body?: unknown, token?: string) => {
    const res = await engine.handle(method, path, body, token);
    if (res.status >= 300) throw new Error(`seed: ${method} ${path} -> ${res.status} ${JSON.stringify(res.body)}`);
    return res.body;
  };
  const { token } = await call("POST", "/api/auth/register", { username: DEMO.username, displayName: "SecOps analyst", password: DEMO.password });
  const site = async (name: string, kind: string, presetKey: string) => (await call("POST", "/api/sites", { name, kind, presetKey }, token)).id as string;
  const asset = (siteId: string, productKey: string, version: string, label?: string) => call("POST", "/api/assets", { siteId, productKey, version, label }, token);

  // Hand-written sites: the README's stories.
  const inference = await site("Inference cluster", "cloud", "ashburn");
  await asset(inference, "ollama", "0.1.33", "Ollama model server");      // CVE-2024-37032 "Probllama"
  await asset(inference, "vllm", "0.11.0", "vLLM gateway");
  await asset(inference, "ray", "2.40.0", "Ray Serve");                   // CVE-2025-62593, in CISA KEV
  await asset(inference, "nginx", "1.27.4", "Ingress nginx");
  const training = await site("Training cluster", "cloud", "eemshaven");
  await asset(training, "pytorch", "2.5.1");                              // CVE-2025-32434, torch.load RCE
  await asset(training, "ray", "2.56.0", "Ray Train");
  await asset(training, "mlflow", "3.17.2", "MLflow tracking");
  await asset(training, "kubernetes", "1.34.2");
  const hq = await site("São Paulo HQ", "office", "sao-paulo");
  await asset(hq, "openssh", "9.6p1", "Bastion sshd");                     // CVE-2024-6387 regreSSHion
  await asset(hq, "gradio", "6.16.0", "Internal demo UIs");
  await asset(hq, "langchain", "1.3.9", "Support assistant");
  const lab = await site("Tokyo research lab", "office", "tokyo");
  await asset(lab, "transformers", "5.10.0");
  await asset(lab, "llama-index", "0.13.0");
  await asset(lab, "jupyter-server", "", "Shared notebooks (version unknown)");
  const dc = await site("Frankfurt data center", "datacenter", "frankfurt");
  await asset(dc, "log4j", "2.25.5", "Log4j in billing service");
  await asset(dc, "openssl", "4.0.3");
  await asset(dc, "nginx", "1.29.3");
  const edge = await site("Singapore edge", "datacenter", "singapore");
  await asset(edge, "nginx", "1.29.3");
  await asset(edge, "openssl", "4.0.3");

  // Generated sites.
  const releases = releasesFromData(snapshot.vulnerabilities);
  const rand = mulberry32(20261112);
  for (const [presetKey, kind, template, hygiene] of GENERATED) {
    const preset = catalog.sitePresets.find((p) => p.key === presetKey)!;
    const t = TEMPLATES[template];
    const where = kind === "cloud" ? regionOf(preset.label) ?? cityOf(preset.label) : cityOf(preset.label);
    const id = await site(`${t.label} · ${where}`, kind, presetKey);
    for (const productKey of t.products) {
      // not every site runs the whole template
      if (t.products.length > 2 && rand() < 0.2) continue;
      const list = releases.get(productKey) ?? [];
      let version = "";
      if (list.length) {
        const spots = SPOTS[hygiene];
        const spot = spots[Math.floor(rand() * spots.length)];
        version = list[Math.min(list.length - 1, Math.round(spot * (list.length - 1)))];
      }
      await asset(id, productKey, version);
    }
  }

  await call("POST", "/api/subscriptions", { name: "Exploited in the wild", scope: "all", minSeverity: "low", kevOnly: true }, token);
  await call("POST", "/api/subscriptions", { name: "Critical with exploit signal", scope: "all", minSeverity: "critical", minEpss: 0.1 }, token);
  await call("POST", "/api/subscriptions", { name: "Inference cluster, high and up", scope: "site", scopeSiteId: inference, minSeverity: "high", webhookUrl: "https://hooks.example.com/blast-radius" }, token);
  engine.state.sessions = {};
}
