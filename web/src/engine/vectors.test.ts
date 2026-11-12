// shared/vectors.json: the same cases run in BlastRadius.Tests/VectorTests.cs.
import { describe as group, expect, test } from "vitest";
import vectors from "@shared/vectors.json";
import { type AffectedRange, best, compareVersions, dangerLevel, dangerScore, evaluate, packageKey, rangeFromGhsa, rangeFromNvd } from "./matching";

group("versions", () => {
  test.each(vectors.compare as [string, string, number][])("%s vs %s", (a, b, want) => {
    expect(Math.sign(compareVersions(a, b))).toBe(want);
    expect(Math.sign(compareVersions(b, a))).toBe(-want || 0);
  });
});

group("GitHub ranges", () => {
  test.each(vectors.ghsaRanges)("$version in $range", ({ range, version, expect: want }) => {
    expect(evaluate(rangeFromGhsa("pip", "x", range, null), version)).toBe(want);
  });
});

group("NVD cpe matches", () => {
  test.each(vectors.nvdCriteria as unknown as { match: Record<string, string>; version: string; expect: string }[])("$version vs $match.criteria", ({ match, version, expect: want }) => {
    const r = rangeFromNvd(match.criteria, match.versionStartIncluding, match.versionStartExcluding, match.versionEndIncluding, match.versionEndExcluding);
    expect(r).not.toBeNull();
    expect(evaluate(r!, version)).toBe(want);
  });
});

group("precedence across sources", () => {
  test.each(vectors.precedence)("$about", ({ ranges, version, expect: want }) => {
    expect(best(ranges as AffectedRange[], version).status).toBe(want);
  });
});

test("package names", () => {
  for (const [eco, a, b, same] of vectors.packageNames as [string, string, string, boolean][]) {
    expect(packageKey(eco, a) === packageKey(eco, b)).toBe(same);
  }
});

test("danger", () => {
  for (const c of vectors.danger) {
    const score = dangerScore(c.cvss, c.severity, c.kev, c.epss, c.status as "affected" | "possible");
    expect(score).toBe(c.expect);
    expect(dangerLevel(score)).toBe(c.level);
  }
});
