import { geoGraticule10, geoInterpolate, geoNaturalEarth1, geoPath, type GeoProjection } from "d3-geo";
import { useEffect, useRef, useState } from "react";
import { feature } from "topojson-client";
import land110 from "world-atlas/land-110m.json";
import type { ExposureSite, Level } from "./api/types";

export const LEVEL_GLOW: Record<Level, string> = {
  clear: "#3fc4a8", low: "#d6c13a", elevated: "#ff9f2e", high: "#ff5a36", severe: "#ff2e4d",
};
const PULSE_SECONDS: Record<Level, number> = { clear: 0, low: 0, elevated: 3.4, high: 2.2, severe: 1.3 };
const SWEEP_SECONDS = 9;

// Starting points for the simulated probe traces: spread around the globe, not attribution.
const ORIGINS: [number, number][] = [
  [-74, 40.7], [-118.2, 34.05], [-87.6, 41.9], [-99.1, 19.4], [-58.4, -34.6], [-43.2, -22.9], [-0.1, 51.5], [2.35, 48.86],
  [13.4, 52.5], [37.6, 55.75], [28.98, 41], [31.2, 30], [3.4, 6.45], [36.8, -1.3], [18.4, -33.9], [55.3, 25.2], [77.2, 28.6],
  [90.4, 23.8], [100.5, 13.75], [106.8, -6.2], [121.5, 31.2], [114.2, 22.3], [139.7, 35.7], [151.2, -33.9], [174.8, -36.85],
  [-123.1, 49.3], [-79.4, 43.7], [-70.6, -33.4], [44.5, 40.2], [69.3, 41.3],
];

export interface Layers { probes: boolean; sweep: boolean }
/** Space taken by docked panels; the world is fitted into what's left so no site hides under glass. */
export interface Insets { left: number; right: number }

interface Probe { site: string; interp: (t: number) => [number, number]; start: number; duration: number; color: string }
interface Pin { site: ExposureSite; x: number; y: number; r: number; angle: number; lastPing: number }

const reducedMotion = () => typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

function hexA(hex: string, a: number) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

export function WorldRadar({ sites, selected, highlight, layers, insets, onSelect }: {
  sites: ExposureSite[];
  selected: string | null;
  highlight: Set<string> | null;
  layers: Layers;
  insets: Insets;
  onSelect: (id: string | null) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [tip, setTip] = useState<{ x: number; y: number; site: ExposureSite } | null>(null);
  const live = useRef({ sites, selected, highlight, layers, insets, hovered: null as string | null });
  live.current = { ...live.current, sites, selected, highlight, layers, insets };
  const relayout = useRef<() => void>(() => undefined);
  useEffect(() => relayout.current(), [insets.left, insets.right]);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  useEffect(() => {
    const el = box.current!;
    const cv = canvas.current!;
    const ctx = cv.getContext("2d")!;
    const still = reducedMotion();
    const land = feature(land110 as any, (land110 as any).objects.land) as any;

    let w = 0, h = 0, dpr = 1;
    let projection: GeoProjection = geoNaturalEarth1();
    let base: HTMLCanvasElement | null = null;
    let pins: Pin[] = [];
    let probes: Probe[] = [];
    const debt = new Map<string, number>();
    let raf = 0;
    let lastT = performance.now();
    let prevSweep = 0;
    let pinsFor: ExposureSite[] | null = null;

    const layout = () => {
      const r = el.getBoundingClientRect();
      w = Math.max(1, r.width); h = Math.max(1, r.height); dpr = Math.min(2, window.devicePixelRatio || 1);
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
      const wide = w > 900;
      const { left, right } = live.current.insets;
      projection = geoNaturalEarth1().fitExtent(
        wide ? [[left, 84], [Math.max(left + 200, w - right), h - 20]] : [[8, 64], [w - 8, h - 8]], { type: "Sphere" });

      // land as a dot matrix: rasterize the land shape once, then sample it on a grid
      const mask = document.createElement("canvas");
      mask.width = Math.round(w); mask.height = Math.round(h);
      const m = mask.getContext("2d", { willReadFrequently: true })!;
      m.beginPath(); geoPath(projection, m)(land); m.fillStyle = "#fff"; m.fill();
      const px = m.getImageData(0, 0, mask.width, mask.height).data;

      base = document.createElement("canvas");
      base.width = cv.width; base.height = cv.height;
      const b = base.getContext("2d")!;
      b.scale(dpr, dpr);
      const glow = b.createRadialGradient(w * 0.55, h * 0.5, 0, w * 0.55, h * 0.5, Math.hypot(w, h) * 0.6);
      glow.addColorStop(0, "#0a121b"); glow.addColorStop(1, "#03060a");
      b.fillStyle = glow; b.fillRect(0, 0, w, h);
      const path = geoPath(projection, b);
      b.beginPath(); path(geoGraticule10()); b.strokeStyle = "rgba(110,190,175,0.045)"; b.lineWidth = 0.6; b.stroke();
      b.beginPath(); path({ type: "Sphere" }); b.strokeStyle = "rgba(95,224,192,0.12)"; b.lineWidth = 1; b.stroke();
      const step = w > 1400 ? 6 : 5;
      b.fillStyle = "rgba(120,150,170,0.3)";
      for (let y = step / 2; y < h; y += step)
        for (let x = step / 2; x < w; x += step) {
          const i = (Math.floor(y) * mask.width + Math.floor(x)) * 4 + 3;
          if (px[i] > 0) { b.beginPath(); b.arc(x, y, 1.05, 0, Math.PI * 2); b.fill(); }
        }
      pinsFor = null;
    };
    relayout.current = () => { layout(); if (still) frame(performance.now()); };

    const placePins = () => {
      const cx = w / 2, cy = h / 2;
      const prev = new Map(pins.map((p) => [p.site.id, p.lastPing]));
      pins = live.current.sites.flatMap((s) => {
        const p = projection([s.lon, s.lat]);
        if (!p) return [];
        const angle = (Math.atan2(p[1] - cy, p[0] - cx) + Math.PI * 2) % (Math.PI * 2);
        return [{ site: s, x: p[0], y: p[1], r: 2.6 + Math.min(3.4, s.assets * 0.55), angle, lastPing: prev.get(s.id) ?? -1e9 }];
      });
      pinsFor = live.current.sites;
    };

    const spawn = (now: number, dt: number) => {
      if (probes.length > 90) return;
      for (const pin of pins) {
        const pressure = pin.site.exploitPressure;
        if (pressure < 0.05) continue;
        const d = (debt.get(pin.site.id) ?? 0) + dt * pressure * 0.11;
        if (d < 1) { debt.set(pin.site.id, d); continue; }
        debt.set(pin.site.id, d - 1);
        const candidates = ORIGINS.filter(([lon, lat]) => Math.hypot(lon - pin.site.lon, lat - pin.site.lat) > 25);
        const origin = candidates[Math.floor(Math.random() * candidates.length)];
        probes.push({
          site: pin.site.id, interp: geoInterpolate(origin, [pin.site.lon, pin.site.lat]), start: now,
          duration: 2400 + Math.random() * 1800, color: pin.site.kev > 0 ? "255,46,77" : "255,159,46",
        });
      }
    };

    const label = (p: Pin, strong: boolean, taken: { x: number; y: number; w: number }[]) => {
      const text = p.site.name;
      ctx.font = `${strong ? 600 : 500} 11px "JetBrains Mono", monospace`;
      const tw = ctx.measureText(text).width;
      const right = p.x + p.r + 8 + tw < w - 8;
      const x = right ? p.x + p.r + 8 : p.x - p.r - 8 - tw;
      const y = p.y + 4;
      // skip a label that would overlap one already drawn (strong labels are drawn first)
      if (taken.some((t) => x - 4 < t.x + t.w && t.x < x + tw + 4 && Math.abs(t.y - y) < 15)) return;
      taken.push({ x: x - 4, y, w: tw + 8 });
      ctx.fillStyle = "rgba(4,7,11,0.72)";
      ctx.fillRect(x - 4, y - 11, tw + 8, 15);
      ctx.fillStyle = strong ? "#eef4f8" : "rgba(190,205,215,0.85)";
      ctx.fillText(text, x, y);
    };

    const frame = (now: number) => {
      const dt = Math.min(0.1, (now - lastT) / 1000);
      lastT = now;
      if (pinsFor !== live.current.sites) placePins();
      const { selected, highlight, layers, hovered } = live.current;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      if (base) ctx.drawImage(base, 0, 0, w, h);
      const cx = w / 2, cy = h / 2, R = Math.hypot(w, h) / 2;

      const sweep = still ? 0 : ((now / 1000 / SWEEP_SECONDS) * Math.PI * 2) % (Math.PI * 2);
      if (!still) {
        if (layers.sweep) {
          const trail = 0.7;
          const grad = ctx.createConicGradient(sweep - trail, cx, cy);
          grad.addColorStop(0, "rgba(95,224,192,0)");
          grad.addColorStop(trail / (Math.PI * 2), "rgba(95,224,192,0.1)");
          grad.addColorStop(trail / (Math.PI * 2) + 0.0001, "rgba(95,224,192,0)");
          ctx.fillStyle = grad;
          ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, R, sweep - trail, sweep); ctx.closePath(); ctx.fill();
          ctx.strokeStyle = "rgba(95,224,192,0.35)"; ctx.lineWidth = 1;
          ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(sweep) * R, cy + Math.sin(sweep) * R); ctx.stroke();
          for (const p of pins) {
            const passed = prevSweep <= sweep ? p.angle > prevSweep && p.angle <= sweep : p.angle > prevSweep || p.angle <= sweep;
            if (passed) p.lastPing = now;
          }
        }
        prevSweep = sweep;
        if (layers.probes) spawn(now, dt);
      }

      // simulated probe traces
      if (!layers.probes) probes = [];
      probes = probes.filter((pr) => now - pr.start < pr.duration + 700);
      for (const pr of probes) {
        const t = Math.min(1, (now - pr.start) / pr.duration);
        const eased = 1 - Math.pow(1 - t, 2);
        const tail = Math.max(0, eased - 0.18);
        ctx.lineWidth = 1.2;
        let prevPt: [number, number] | null = null;
        for (let i = 0; i <= 14; i++) {
          const u = tail + ((eased - tail) * i) / 14;
          const pt = projection(pr.interp(u));
          if (!pt) { prevPt = null; continue; }
          if (prevPt && Math.abs(pt[0] - prevPt[0]) < w / 3) {
            ctx.strokeStyle = `rgba(${pr.color},${(0.7 * i) / 14})`;
            ctx.beginPath(); ctx.moveTo(prevPt[0], prevPt[1]); ctx.lineTo(pt[0], pt[1]); ctx.stroke();
          }
          prevPt = pt;
        }
        if (t < 1 && prevPt) { ctx.fillStyle = `rgba(${pr.color},0.95)`; ctx.beginPath(); ctx.arc(prevPt[0], prevPt[1], 1.6, 0, Math.PI * 2); ctx.fill(); }
        if (t >= 1) {
          const pin = pins.find((p) => p.site.id === pr.site);
          const k = (now - pr.start - pr.duration) / 700;
          if (pin) { ctx.strokeStyle = `rgba(${pr.color},${0.6 * (1 - k)})`; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(pin.x, pin.y, pin.r + 2 + 10 * k, 0, Math.PI * 2); ctx.stroke(); }
        }
      }

      // sites, least dangerous first so red draws on top
      const order = [...pins].sort((a, b) => a.site.score - b.site.score);
      for (const p of order) {
        const color = LEVEL_GLOW[p.site.level];
        const dimmed = highlight != null && !highlight.has(p.site.id);
        const period = PULSE_SECONDS[p.site.level];
        if (period > 0 && !dimmed) {
          const phase = still ? 0.5 : (now / 1000 / period) % 1;
          ctx.strokeStyle = hexA(color, 0.5 * (1 - phase));
          ctx.lineWidth = 1.1;
          ctx.beginPath(); ctx.arc(p.x, p.y, p.r + phase * (p.site.level === "severe" ? 22 : 15), 0, Math.PI * 2); ctx.stroke();
        }
        const ping = (now - p.lastPing) / 1500;
        if (ping >= 0 && ping < 1 && !dimmed) {
          ctx.strokeStyle = `rgba(95,224,192,${0.5 * (1 - ping)})`; ctx.lineWidth = 1.2;
          ctx.beginPath(); ctx.arc(p.x, p.y, p.r + 3 + ping * 12, 0, Math.PI * 2); ctx.stroke();
        }
        ctx.globalAlpha = dimmed ? 0.25 : 1;
        ctx.shadowColor = color; ctx.shadowBlur = dimmed ? 0 : 12;
        ctx.fillStyle = color;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
        ctx.fillStyle = "#04070b"; ctx.beginPath(); ctx.arc(p.x, p.y, Math.max(1.2, p.r * 0.35), 0, Math.PI * 2); ctx.fill();
        ctx.globalAlpha = 1;
        if (highlight?.has(p.site.id)) {
          ctx.strokeStyle = "rgba(238,244,248,0.9)"; ctx.lineWidth = 1.3;
          ctx.beginPath(); ctx.arc(p.x, p.y, p.r + 5, 0, Math.PI * 2); ctx.stroke();
        }
        if (selected === p.site.id) {
          ctx.strokeStyle = "rgba(255,255,255,0.95)"; ctx.lineWidth = 1.3;
          const s = p.r + 9;
          for (const [dx, dy] of [[-1, -1], [1, -1], [-1, 1], [1, 1]]) {
            ctx.beginPath(); ctx.moveTo(p.x + dx * s, p.y + dy * (s - 5)); ctx.lineTo(p.x + dx * s, p.y + dy * s); ctx.lineTo(p.x + dx * (s - 5), p.y + dy * s); ctx.stroke();
          }
        }
      }
      // labels on demand: selected and hovered first, then highlighted
      const taken: { x: number; y: number; w: number }[] = [];
      for (const p of order) if (selected === p.site.id || hovered === p.site.id) label(p, true, taken);
      for (const p of [...order].reverse()) if (highlight?.has(p.site.id) && selected !== p.site.id && hovered !== p.site.id) label(p, false, taken);
      if (!still) raf = requestAnimationFrame(frame);
    };

    const ro = new ResizeObserver(() => { layout(); if (still) frame(performance.now()); });
    ro.observe(el);
    layout();
    if (still) frame(performance.now()); else raf = requestAnimationFrame(frame);

    const nearest = (e: MouseEvent) => {
      const r = el.getBoundingClientRect();
      const x = e.clientX - r.left, y = e.clientY - r.top;
      let best: Pin | null = null, d = 14;
      for (const p of pins) { const dist = Math.hypot(p.x - x, p.y - y) - p.r; if (dist < d) { d = dist; best = p; } }
      return best;
    };
    const move = (e: MouseEvent) => {
      const best = nearest(e);
      live.current.hovered = best?.site.id ?? null;
      setTip(best ? { x: best.x, y: best.y, site: best.site } : null);
      el.style.cursor = best ? "pointer" : "default";
    };
    const click = (e: MouseEvent) => onSelectRef.current(nearest(e)?.site.id ?? null);
    const leave = () => { live.current.hovered = null; setTip(null); };
    el.addEventListener("mousemove", move);
    el.addEventListener("click", click);
    el.addEventListener("mouseleave", leave);
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      el.removeEventListener("mousemove", move);
      el.removeEventListener("click", click);
      el.removeEventListener("mouseleave", leave);
    };
  }, []);

  return (
    <div className="map" ref={box} role="img" aria-label={`World map of ${sites.length} sites colored by exposure`}>
      <canvas ref={canvas} />
      {tip && (
        <div className="radar-tip glass" style={{ left: tip.x, top: tip.y }}>
          <b>{tip.site.name}</b>
          <span className={`lvl lvl-${tip.site.level}`}>{tip.site.level} · {tip.site.score.toFixed(1)}</span>
          <div className="dim" style={{ marginTop: 4 }}>{tip.site.assets} products · {tip.site.affected} vulnerabilities confirmed by version{tip.site.possible ? `, ${tip.site.possible} possible` : ""}</div>
          {tip.site.kev > 0 && <div style={{ color: "#ff6b80" }}>{tip.site.kev} exploited in the wild</div>}
          {tip.site.top && <div className="faint" style={{ marginTop: 4 }}>Worst: {tip.site.top.id}</div>}
          <div className="faint" style={{ marginTop: 4, fontSize: 11.5 }}>Click for the software installed here</div>
        </div>
      )}
    </div>
  );
}
