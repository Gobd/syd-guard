import { createTheme, globalStyle, style } from "@vanilla-extract/css";
export const [theme, vars] = createTheme({
  color: {
    bg: "#10151e",
    panel: "#1b2432",
    text: "#f1f5fa",
    muted: "#acb9ce",
    border: "#39485f",
    accent: "#82c6ff",
    danger: "#ffaaa3",
  },
  space: { sm: "8px", md: "16px", lg: "24px" },
});
globalStyle("body", {
  margin: 0,
  background: "#10151e",
  color: "#f1f5fa",
  fontFamily: "system-ui, sans-serif",
});
globalStyle("*", { boxSizing: "border-box" });
export const page = style({
  maxWidth: "1100px",
  margin: "0 auto",
  padding: vars.space.lg,
});
export const panel = style({
  background: vars.color.panel,
  border: `1px solid ${vars.color.border}`,
  borderRadius: "12px",
  padding: vars.space.md,
  marginBottom: vars.space.md,
});
export const muted = style({ color: vars.color.muted });
export const row = style({
  display: "flex",
  gap: vars.space.sm,
  alignItems: "center",
  flexWrap: "wrap",
});
export const button = style({
  cursor: "pointer",
  border: `1px solid ${vars.color.border}`,
  background: "#26364b",
  color: vars.color.text,
  padding: "8px 14px",
  borderRadius: "6px",
  ":focus-visible": { outline: `2px solid ${vars.color.accent}` },
  ":disabled": { opacity: 0.5, cursor: "wait" },
});
export const input = style({
  background: vars.color.bg,
  color: vars.color.text,
  border: `1px solid ${vars.color.border}`,
  padding: "10px",
  borderRadius: "6px",
  width: "100%",
});
export const warning = style({
  color: vars.color.danger,
  overflowWrap: "anywhere",
});
