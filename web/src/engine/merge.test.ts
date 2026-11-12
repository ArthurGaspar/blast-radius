// Mirrors BlastRadius.Tests/MergeTests.cs on the same recorded responses.
import { expect, test } from "vitest";
import nvdOllama from "@shared/fixtures/day2/nvd/ollama_ollama.json";
import ghsaOllama from "@shared/fixtures/day2/ghsa/go/github.com_ollama_ollama.json";
import { type Advisory, absorb, apply, cveOf, emptyVulnerability, fromGhsa, fromNvd, preferredId } from "./merge";

const NOW = "2026-11-12T00:00:00.000Z";
const nvd = (id: string) => fromNvd((nvdOllama as any).vulnerabilities.map((x: any) => x.cve).find((c: any) => c.id === id));
const ghsa = (id: string) => fromGhsa((ghsaOllama as any[]).find((a) => a.ghsa_id === id));
const fold = (...advisories: Advisory[]) => {
  const v = emptyVulnerability(preferredId(advisories.flatMap((a) => a.aliases)), NOW);
  for (const a of advisories) apply(v, a, NOW);
  return v;
};

test("GitHub and NVD describe the same CVE", () => {
  const n = nvd("CVE-2024-37032");
  const g = ghsa("GHSA-8hqg-whrw-pv92");
  expect(cveOf(g)).toBe("CVE-2024-37032");
  expect(g.severity).toBe("medium");
  expect(n.cvssScore).toBe(8.8);
  const v = fold(n, g);
  expect(v.id).toBe("CVE-2024-37032");
  expect(v.aliases).toEqual(["CVE-2024-37032", "GHSA-8hqg-whrw-pv92"]);
  expect(v.sources).toEqual(["ghsa", "nvd"]);
  expect([v.cvssScore, v.cvssSource, v.severity, v.titleSource]).toEqual([8.8, "nvd", "high", "ghsa"]);
  expect(v.title.startsWith("Ollama")).toBe(true);
  expect(v.ranges).toHaveLength(2);
});

test("merging is independent of arrival order", () => {
  const a = fold(nvd("CVE-2024-37032"), ghsa("GHSA-8hqg-whrw-pv92"));
  const b = fold(ghsa("GHSA-8hqg-whrw-pv92"), nvd("CVE-2024-37032"));
  const pick = (v: typeof a) => [v.title, v.description, v.cvssScore, v.severity, v.published, v.modified, v.aliases, v.sources, v.ranges];
  expect(pick(a)).toEqual(pick(b));
});

test("re-applying the same advisory changes nothing", () => {
  const v = fold(nvd("CVE-2024-37032"), ghsa("GHSA-8hqg-whrw-pv92"));
  expect(apply(v, ghsa("GHSA-8hqg-whrw-pv92"), NOW)).toBe(false);
  expect(apply(v, nvd("CVE-2024-37032"), NOW)).toBe(false);
});

test("a source replaces only its own ranges", () => {
  const v = fold(nvd("CVE-2024-37032"), ghsa("GHSA-8hqg-whrw-pv92"));
  apply(v, { ...ghsa("GHSA-8hqg-whrw-pv92"), withdrawn: true }, NOW);
  expect(v.ranges.every((r) => r.source === "nvd")).toBe(true);
  expect(v.withdrawn).toBe(false);
});

test("absorbing a duplicate keeps the best of both", () => {
  const cve = fold(nvd("CVE-2024-37032"));
  const gh = fold({ ...ghsa("GHSA-8hqg-whrw-pv92"), aliases: ["GHSA-8hqg-whrw-pv92"] });
  expect(gh.id).toBe("GHSA-8hqg-whrw-pv92");
  gh.kev = true;
  absorb(cve, gh);
  expect(cve.aliases).toContain("GHSA-8hqg-whrw-pv92");
  expect([cve.cvssSource, cve.titleSource, cve.kev, cve.ranges.length]).toEqual(["nvd", "ghsa", true, 2]);
});
