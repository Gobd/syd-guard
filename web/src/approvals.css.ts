import { style } from "@vanilla-extract/css";
import { vars } from "./theme.css";
export const target = style({
  fontFamily: "ui-monospace, monospace",
  overflowWrap: "anywhere",
  whiteSpace: "pre-wrap",
  background: vars.color.bg,
  padding: vars.space.sm,
  borderRadius: "6px",
  margin: "12px 0",
});
export const badge = style({
  color: vars.color.accent,
  fontSize: "13px",
  fontWeight: 600,
});
