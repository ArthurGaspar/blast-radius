// Plays shared/contract/scenario.json against the browser engine on the recorded fixtures.
// BlastRadius.Tests/ContractRunner.cs plays the same file against the ASP.NET Core API.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import scenario from "@shared/contract/scenario.json";
import { Engine, emptyState } from "./engine";
import { fixtureFetcher } from "./sources";

const fixtures = fileURLToPath(new URL("../../../shared/fixtures/", import.meta.url));
let day = "day1";
const fetcher = fixtureFetcher((path) => {
  const file = `${fixtures}${day}/${path}`;
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf-8")) : undefined;
});

export function select(root: unknown, path: string): unknown {
  if (root == null) return undefined;
  const length = path.endsWith("#");
  let node: any = root;
  for (const m of (length ? path.slice(0, -1) : path).slice(1).matchAll(/\.([A-Za-z0-9_]+)|\[(\d+)\]/g)) {
    if (node == null) return undefined;
    node = m[1] != null ? node[m[1]] : node[Number(m[2])];
  }
  if (node === undefined) return undefined;
  return length ? (Array.isArray(node) ? node.length : Object.keys(node).length) : node;
}

function satisfies(got: unknown, want: any): boolean {
  if (want && typeof want === "object" && !Array.isArray(want)) {
    const [[op, arg]] = Object.entries(want) as [string, any][];
    if (op === "contains") return typeof got === "string" && got.includes(arg);
    if (typeof got !== "number") return false;
    return op === "gt" ? got > arg : op === "gte" ? got >= arg : got < arg;
  }
  return JSON.stringify(got) === JSON.stringify(want);
}

describe("contract scenario on the browser engine", () => {
  const engine = new Engine(emptyState(), { fetcher, live: false, manualCooldownMinutes: 0 });
  const saved = new Map<string, any>();
  const interpolate = (s: string) => s.replace(/\{([A-Za-z0-9:]+)\}/g, (_, k) => {
    if (!saved.has(k)) throw new Error(`nothing saved as ${k}`);
    return String(saved.get(k));
  });
  const substitute = (node: any): any => {
    if (typeof node === "string") { const m = /^\{([A-Za-z0-9:]+)\}$/.exec(node); return m ? saved.get(m[1]) : interpolate(node); }
    if (Array.isArray(node)) return node.map(substitute);
    if (node && typeof node === "object") return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, substitute(v)]));
    return node;
  };

  (scenario.steps as any[]).forEach((step, i) => {
    if (step.fixtures) {
      test(`${String(i + 1).padStart(2, "0")} switch to ${step.fixtures}`, () => { day = step.fixtures; });
      return;
    }
    test(`${String(i + 1).padStart(2, "0")} ${step.name}`, async () => {
      const token = step.as ? saved.get(`token:${step.as}`) : null;
      const res = await engine.handle(step.method, interpolate(step.path), step.body === undefined ? undefined : substitute(step.body), token);
      const text = JSON.stringify(res.body)?.slice(0, 600);
      expect(res.status, `status; body ${text}`).toBe(step.expect.status);
      if (step.expect.code) expect(res.body?.code, `code; body ${text}`).toBe(step.expect.code);
      for (const [path, want] of Object.entries(step.expect.json ?? {}))
        expect(satisfies(select(res.body, path), want), `${path} expected ${JSON.stringify(want)} got ${JSON.stringify(select(res.body, path))}; body ${text}`).toBe(true);
      for (const [key, path] of Object.entries(step.save ?? {})) {
        const v = select(res.body, path as string);
        if (v == null) throw new Error(`nothing at ${path} to save as ${key}`);
        saved.set(key, v);
      }
    });
  });
});
