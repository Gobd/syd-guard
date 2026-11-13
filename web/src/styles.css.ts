import {
  createGlobalTheme,
  globalStyle,
  style,
  styleVariants,
} from "@vanilla-extract/css";

export const vars = createGlobalTheme(":root", {
  bg: "#fafafa",
  card: "#fff",
  fg: "#1d1d1f",
  mute: "#6e6e73",
  line: "#e3e3e8",
  accent: "#0a66ff",
  warn: "#c2410c",
  ok: "#15803d",
  mono: "ui-monospace, SFMono-Regular, Menlo, monospace",
});

globalStyle(":root", {
  colorScheme: "light dark",
  "@media": {
    "(prefers-color-scheme: dark)": {
      vars: {
        [vars.bg]: "#111214",
        [vars.card]: "#1b1c1f",
        [vars.fg]: "#ececf1",
        [vars.mute]: "#9a9aa3",
        [vars.line]: "#2c2d32",
        [vars.accent]: "#5b9bff",
        [vars.warn]: "#fb923c",
        [vars.ok]: "#4ade80",
      },
    },
  },
});
globalStyle("*", { boxSizing: "border-box" });
globalStyle("body", {
  margin: 0,
  font: "14px/1.45 -apple-system, system-ui, sans-serif",
  background: vars.bg,
  color: vars.fg,
});
globalStyle("input, select", {
  font: `13px ${vars.mono}`,
  padding: "5px 8px",
  border: `1px solid ${vars.line}`,
  borderRadius: 6,
  background: vars.bg,
  color: vars.fg,
});
globalStyle("button", {
  font: "inherit",
  fontSize: 13,
  padding: "5px 12px",
  borderRadius: 6,
  border: `1px solid ${vars.line}`,
  background: vars.card,
  color: vars.fg,
  cursor: "pointer",
});

export const header = style({
  display: "flex",
  alignItems: "baseline",
  gap: 12,
  padding: "14px 24px",
  borderBottom: `1px solid ${vars.line}`,
});
export const title = style({ fontSize: 17, margin: 0 });
export const main = style({
  maxWidth: 1150,
  margin: "0 auto",
  padding: "16px 24px 64px",
});
export const section = style({
  fontSize: 13,
  textTransform: "uppercase",
  letterSpacing: ".06em",
  color: vars.mute,
  margin: "28px 0 10px",
  display: "flex",
  gap: 10,
  alignItems: "center",
});
export const card = style({
  background: vars.card,
  border: `1px solid ${vars.line}`,
  borderRadius: 10,
  padding: "12px 14px",
  marginBottom: 10,
});
export const row = style({
  display: "flex",
  gap: 8,
  alignItems: "center",
  flexWrap: "wrap",
});
export const grow = style({ flex: 1, minWidth: 260 });
export const target = style({
  font: `13px ${vars.mono}`,
  wordBreak: "break-all",
});
export const mute = style({ color: vars.mute, fontSize: 12 });
export const warn = style({ color: vars.warn, fontSize: 12 });
export const ok = style({ color: vars.ok, fontSize: 12 });
export const toast = style({
  whiteSpace: "pre-wrap",
  fontSize: 12,
  minHeight: 16,
});
export const empty = style({ color: vars.mute, padding: "8px 2px" });
export const primary = style({
  background: vars.accent,
  borderColor: vars.accent,
  color: "#fff",
});
export const link = style({
  border: "none",
  background: "none",
  color: vars.mute,
  padding: "2px 6px",
  ":hover": { color: vars.warn },
});

const pillBase = style({
  font: `600 11px ${vars.mono}`,
  padding: "2px 7px",
  borderRadius: 5,
  background: vars.line,
  textTransform: "uppercase",
});
const tint = (c: string, pct: number) => ({
  background: `color-mix(in srgb, ${c} ${pct}%, transparent)`,
});
export const pill = styleVariants({
  plain: [pillBase],
  warn: [pillBase, tint(vars.warn, 25)],
  web: [pillBase, tint(vars.accent, 22)],
  ok: [pillBase, tint(vars.ok, 22)],
});

export const opts = style({
  display: "flex",
  gap: 6,
  flexWrap: "wrap",
  margin: "8px 0",
});
export const opt = style({ font: `12px ${vars.mono}`, padding: "3px 8px" });
export const optSelected = style([
  opt,
  { borderColor: vars.accent, color: vars.accent },
]);

export const rulesGrid = style({
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))",
  gap: 10,
  marginTop: 8,
});
export const ruleList = style({
  listStyle: "none",
  margin: "4px 0 6px",
  padding: 0,
});
export const ruleItem = style({
  display: "flex",
  justifyContent: "space-between",
  gap: 6,
  font: `12.5px ${vars.mono}`,
  padding: "2px 0",
  wordBreak: "break-all",
});
export const ruleHead = style({
  margin: 0,
  fontSize: 12,
  color: vars.mute,
  textTransform: "uppercase",
});
export const addRow = style({ display: "flex", gap: 4 });
export const addInput = style({ minWidth: 0, flex: 1, fontSize: 12 });
export const pre = style({
  font: `12px ${vars.mono}`,
  background: vars.bg,
  border: `1px solid ${vars.line}`,
  borderRadius: 6,
  padding: 8,
  overflow: "auto",
  maxHeight: 240,
});
export const summary = style({
  cursor: "pointer",
  color: vars.mute,
  fontSize: 12,
  marginTop: 6,
});
