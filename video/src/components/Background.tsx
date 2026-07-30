import { AbsoluteFill, useCurrentFrame, useVideoConfig, interpolate, Easing } from "remotion";
import { COLORS, EASE_OUT } from "../theme";

// Persistent navy-gradient background with a slow-drifting glow orb grid and
// faint engineering-style grid lines. Shared across all scenes for consistency.
export const Background: React.FC<{ sceneFrame?: number }> = ({ sceneFrame: _f }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();

  // Grid lines fade in once at the very start, then stay.
  const gridOpacity = interpolate(frame, [0, 45], [0, 1], {
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });

  // Two glow orbs drift slowly across the frame for life.
  const t = frame / durationInFrames;
  const orb1x = interpolate(t, [0, 1], ["12%", "78%"]);
  const orb1y = interpolate(t, [0, 1], ["22%", "68%"]);
  const orb2x = interpolate(t, [0, 1], ["82%", "18%"]);
  const orb2y = interpolate(t, [0, 1], ["72%", "30%"]);

  return (
    <AbsoluteFill
      style={{
        background: `radial-gradient(120% 120% at 50% 0%, ${COLORS.bgMid} 0%, ${COLORS.bgDeep} 55%, #0b1020 100%)`,
      }}
    >
      {/* Drifting glow orbs */}
      <div
        style={{
          position: "absolute",
          left: orb1x,
          top: orb1y,
          width: 720,
          height: 720,
          marginLeft: -360,
          marginTop: -360,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${COLORS.blue}22 0%, transparent 60%)`,
          filter: "blur(40px)",
        }}
      />
      <div
        style={{
          position: "absolute",
          left: orb2x,
          top: orb2y,
          width: 640,
          height: 640,
          marginLeft: -320,
          marginTop: -320,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${COLORS.violet}22 0%, transparent 60%)`,
          filter: "blur(40px)",
        }}
      />

      {/* Engineering grid */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          opacity: gridOpacity * 0.5,
          backgroundImage: `linear-gradient(${COLORS.cardBorder} 1px, transparent 1px), linear-gradient(90deg, ${COLORS.cardBorder} 1px, transparent 1px)`,
          backgroundSize: "80px 80px",
          maskImage: "radial-gradient(100% 80% at 50% 50%, black 40%, transparent 85%)",
          WebkitMaskImage: "radial-gradient(100% 80% at 50% 50%, black 40%, transparent 85%)",
        }}
      />

      {/* Subtle top sheen */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 380,
          background: `linear-gradient(180deg, ${COLORS.blue}10 0%, transparent 100%)`,
        }}
      />
    </AbsoluteFill>
  );
};
