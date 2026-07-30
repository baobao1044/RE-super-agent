import { interpolate, Easing } from "remotion";
import { COLORS, EASE_OUT } from "../theme";

// A small pill label — used for badges / tags.
export const Pill: React.FC<{
  children: React.ReactNode;
  color?: string;
  bg?: string;
}> = ({ children, color = COLORS.blueBright, bg = "rgba(59,130,246,0.12)" }) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 12,
      padding: "14px 28px",
      borderRadius: 999,
      fontSize: 38,
      fontWeight: 600,
      color,
      background: bg,
      border: `1px solid ${color}33`,
      whiteSpace: "nowrap",
    }}
  >
    {children}
  </span>
);

// Helper: fade+rise-in element from its slot.
export function useRiseIn(
  frame: number,
  start: number,
  duration = 24,
  fromY = 28
) {
  const opacity = interpolate(frame, [start, start + duration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });
  const translateY = interpolate(frame, [start, start + duration], [fromY, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });
  return { opacity, translateY };
}

// Helper: scale-in with fade.
export function useScaleIn(frame: number, start: number, duration = 24) {
  const opacity = interpolate(frame, [start, start + duration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });
  const scale = interpolate(frame, [start, start + duration], [0.92, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });
  return { opacity, scale };
}

// Monospace "code" chip — for filenames / tool names.
export const Mono: React.FC<{ children: React.ReactNode; color?: string }> = ({
  children,
  color = COLORS.cyan,
}) => (
  <span
    style={{
      fontFamily: "'JetBrains Mono', 'Fira Code', ui-monospace, monospace",
      color,
      fontWeight: 500,
    }}
  >
    {children}
  </span>
);
