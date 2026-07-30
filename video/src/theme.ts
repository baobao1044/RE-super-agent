// Tech-minimalist theme tokens for RE-super-agent intro video.
// Navy gradient base, blue/violet accents, Inter typography.

export const COLORS = {
  // Background
  bgDeep: "#0f172a", // slate-900
  bgMid: "#1e1b4b", // indigo-950
  bgPurple: "#2e1065", // violet-950 (gradient end)

  // Accents
  blue: "#3b82f6",
  blueBright: "#60a5fa",
  violet: "#8b5cff",
  violetBright: "#a78bfa",
  cyan: "#22d3ee",
  green: "#34d399",

  // Text
  textPrimary: "#f1f5f9", // slate-100
  textMuted: "#94a3b8", // slate-400
  textDim: "#64748b", // slate-500

  // Surfaces
  cardBg: "rgba(255, 255, 255, 0.04)",
  cardBorder: "rgba(255, 255, 255, 0.10)",
  cardBorderAccent: "rgba(59, 130, 246, 0.35)",
} as const;

// 1920x1080 composition — scale text up from the 1080-width baseline (~x1.78).
export const FONT = {
  display: 150, // hero title
  h1: 116, // scene headlines
  h2: 84, // supporting headlines
  body: 56, // body / descriptions
  label: 44, // small labels
  micro: 34, // tiny callouts
} as const;

// Shared easing — smooth, slightly overshooting decel.
export const EASE_OUT = [0.16, 1, 0.3, 1] as const;
export const EASE_IN_OUT = [0.65, 0, 0.35, 1] as const;

// Composition: 70s @ 30fps = 2100 frames.
export const FPS = 30;
export const DURATION = 2100;

// Scene boundaries (in frames). Each scene owns its Sequence window.
export const SCENES = {
  title: { from: 0, duration: 7 * FPS }, // 0–7s
  capabilities: { from: 7 * FPS, duration: 13 * FPS }, // 7–20s
  architecture: { from: 20 * FPS, duration: 13 * FPS }, // 20–33s
  deobfuscation: { from: 33 * FPS, duration: 13 * FPS }, // 33–46s
  safety: { from: 46 * FPS, duration: 10 * FPS }, // 46–56s
  workflow: { from: 56 * FPS, duration: 8 * FPS }, // 56–64s
  cta: { from: 64 * FPS, duration: 6 * FPS }, // 64–70s
} as const;
