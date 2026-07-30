import { AbsoluteFill, useCurrentFrame, interpolate, Easing } from "remotion";
import { COLORS, FONT, EASE_OUT } from "../theme";
import { useRiseIn, useScaleIn } from "../components/ui";

// Scene 6 — Dynamic workflow engine (synth → execute → observe → adapt loop).
export const Scene06Workflow: React.FC = () => {
  const frame = useCurrentFrame();
  const header = useRiseIn(frame, 4, 18, 22);

  const nodes = [
    { icon: "✨", label: "Synth", sub: "LLM builds DAG", accent: COLORS.violetBright },
    { icon: "▶️", label: "Execute", sub: "topological", accent: COLORS.blueBright },
    { icon: "👁️", label: "Observe", sub: "outputs", accent: COLORS.cyan },
  ];

  const adapts = ["insert_after", "replace_node", "switch_specialist", "backtrack"];

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 40 }}>
      {/* Header */}
      <div
        style={{
          ...header,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 18,
        }}
      >
        <div
          style={{
            fontFamily: "'JetBrains Mono', ui-monospace, monospace",
            fontSize: 40,
            letterSpacing: 3,
            color: COLORS.violetBright,
            textTransform: "uppercase",
          }}
        >
          Dynamic workflow engine
        </div>
        <div style={{ fontSize: FONT.h2, fontWeight: 700, color: COLORS.textPrimary }}>
          Self-adapts when reality diverges from the plan
        </div>
      </div>

      {/* 3-node row */}
      <div style={{ display: "flex", alignItems: "center", gap: 30 }}>
        {nodes.map((n, i) => {
          const start = 22 + i * 14;
          const rise = useScaleIn(frame, start, 20);
          const arrow = i < nodes.length - 1 ? interpolate(frame, [start + 18, start + 28], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
            easing: Easing.bezier(...EASE_OUT),
          }) : null;
          return (
            <div key={n.label} style={{ display: "flex", alignItems: "center", gap: 30 }}>
              <div
                style={{
                  ...rise,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 12,
                  width: 340,
                  padding: "34px 28px",
                  borderRadius: 24,
                  background: `${n.accent}14`,
                  border: `1px solid ${n.accent}55`,
                }}
              >
                <span style={{ fontSize: 64 }}>{n.icon}</span>
                <span style={{ fontSize: 50, fontWeight: 700, color: COLORS.textPrimary }}>{n.label}</span>
                <span style={{ fontSize: 30, color: COLORS.textMuted }}>{n.sub}</span>
              </div>
              {arrow !== null && (
                <div style={{ opacity: arrow, display: "flex", alignItems: "center" }}>
                  <div style={{ width: 60, height: 3, background: n.accent, opacity: 0.6 }} />
                  <div
                    style={{
                      width: 0,
                      height: 0,
                      borderTop: "10px solid transparent",
                      borderBottom: "10px solid transparent",
                      borderLeft: `14px solid ${n.accent}`,
                      opacity: 0.8,
                    }}
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Anomaly decision + adapt chips */}
      <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
        {/* down arrow */}
        <div
          style={{
            opacity: interpolate(frame, [80, 92], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 8,
          }}
        >
          <div style={{ width: 3, height: 48, background: COLORS.cyan, opacity: 0.6 }} />
          <div
            style={{
              width: 0,
              height: 0,
              borderLeft: "12px solid transparent",
              borderRight: "12px solid transparent",
              borderTop: `14px solid ${COLORS.cyan}`,
            }}
          />
        </div>

        {/* Anomaly? pill */}
        <div
          style={{
            ...useRiseIn(frame, 96, 18, 20),
            display: "flex",
            alignItems: "center",
            gap: 16,
            padding: "22px 40px",
            borderRadius: 999,
            background: "rgba(34,211,238,0.12)",
            border: `1px solid ${COLORS.cyan}66`,
          }}
        >
          <span style={{ fontSize: 44 }}>🤔</span>
          <span style={{ fontSize: 44, fontWeight: 700, color: COLORS.textPrimary }}>Anomaly?</span>
        </div>

        {/* yes arrow */}
        <div
          style={{
            opacity: interpolate(frame, [120, 132], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
            fontSize: 30,
            color: COLORS.violetBright,
            fontWeight: 700,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          yes →
        </div>

        {/* adapt chips */}
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", maxWidth: 720 }}>
          {adapts.map((a, i) => {
            const start = 136 + i * 8;
            const rise = useRiseIn(frame, start, 16, 20);
            return (
              <span
                key={a}
                style={{
                  ...rise,
                  fontFamily: "'JetBrains Mono', ui-monospace, monospace",
                  fontSize: 32,
                  fontWeight: 600,
                  color: COLORS.violetBright,
                  padding: "12px 24px",
                  borderRadius: 14,
                  background: "rgba(139,92,255,0.16)",
                  border: `1px solid ${COLORS.violet}55`,
                }}
              >
                {a}()
              </span>
            );
          })}
        </div>
      </div>

      {/* loop-back arrow label */}
      <div
        style={{
          opacity: interpolate(frame, [176, 188], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
          display: "flex",
          alignItems: "center",
          gap: 12,
          fontSize: 32,
          color: COLORS.textMuted,
          fontFamily: "'JetBrains Mono', ui-monospace, monospace",
        }}
      >
        <span style={{ color: COLORS.violetBright }}>↺</span> re-execute the adapted DAG · checkpoint / resume
      </div>
    </AbsoluteFill>
  );
};
