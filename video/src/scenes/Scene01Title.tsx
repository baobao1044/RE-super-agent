import { AbsoluteFill, useCurrentFrame, interpolate, Easing } from "remotion";
import { COLORS, FONT, EASE_OUT } from "../theme";
import { Pill, useRiseIn, useScaleIn } from "../components/ui";

// Scene 1 — Hero title. "RE-super-agent" + tagline + badge row.
export const Scene01Title: React.FC = () => {
  const frame = useCurrentFrame();

  const eyebrow = useRiseIn(frame, 6, 18);
  const title = useScaleIn(frame, 14, 26);
  const tagline = useRiseIn(frame, 40, 20, 24);
  const badges = useRiseIn(frame, 60, 26, 30);

  // Title gradient text.
  const gradient = `linear-gradient(110deg, ${COLORS.blueBright} 0%, ${COLORS.violetBright} 100%)`;

  // A thin animated underline accent under the title.
  const underlineW = interpolate(frame, [44, 76], [0, 560], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });

  const badgeItems = [
    "5 MCP servers",
    "44 tools",
    "5 specialists",
    "TDD • 298 tests",
  ];

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 44,
          textAlign: "center",
        }}
      >
        {/* Eyebrow */}
        <div
          style={{
            ...eyebrow,
            fontFamily: "'JetBrains Mono', ui-monospace, monospace",
            fontSize: 42,
            letterSpacing: 4,
            color: COLORS.blueBright,
            textTransform: "uppercase",
          }}
        >
          A super agent for professional RE
        </div>

        {/* Title */}
        <div style={{ ...title, display: "flex", flexDirection: "column", alignItems: "center", gap: 18 }}>
          <div
            style={{
              fontSize: FONT.display,
              fontWeight: 800,
              lineHeight: 1,
              letterSpacing: -2,
              background: gradient,
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              color: "transparent",
            }}
          >
            RE-super-agent
          </div>
          {/* underline accent */}
          <div
            style={{
              height: 6,
              width: underlineW,
              borderRadius: 999,
              background: gradient,
            }}
          />
        </div>

        {/* Tagline */}
        <div
          style={{
            ...tagline,
            fontSize: FONT.body,
            fontWeight: 500,
            color: COLORS.textMuted,
            maxWidth: 1320,
            lineHeight: 1.4,
          }}
        >
          Hybrid architecture — MCP tool servers, multi-specialist orchestration,
          an adaptive workflow engine, and a safety-first isolation layer.
        </div>

        {/* Badges */}
        <div
          style={{
            ...badges,
            display: "flex",
            gap: 24,
            flexWrap: "wrap",
            justifyContent: "center",
            marginTop: 12,
          }}
        >
          {badgeItems.map((b) => (
            <Pill key={b}>{b}</Pill>
          ))}
        </div>
      </div>
    </AbsoluteFill>
  );
};
