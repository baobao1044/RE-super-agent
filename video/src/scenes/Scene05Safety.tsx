import { AbsoluteFill, useCurrentFrame, interpolate, Easing } from "remotion";
import { COLORS, FONT, EASE_OUT } from "../theme";
import { useRiseIn, useScaleIn } from "../components/ui";

type Risk = {
  label: string;
  color: string;
  bg: string;
  action: string;
  detail: string;
  refuse?: boolean;
};

const RISKS: Risk[] = [
  {
    label: "LOW",
    color: COLORS.green,
    bg: "rgba(52,211,153,0.12)",
    action: "Docker sandbox",
    detail: "no-network · cap-drop · read-only · tmpfs noexec",
  },
  {
    label: "MEDIUM",
    color: "#f59e0b",
    bg: "rgba(245,158,11,0.12)",
    action: "Qiling-in-Docker",
    detail: "real exec requires human confirmation",
  },
  {
    label: "HIGH",
    color: "#ef4444",
    bg: "rgba(239,68,68,0.14)",
    action: "Static-only",
    detail: "dynamic + code-gen refused",
    refuse: true,
  },
];

const cardW = 380;
const cardH = 340;
const GAP = 40;

// Scene 5 — Safety model. Risk scan → 3 risk tiers.
export const Scene05Safety: React.FC = () => {
  const frame = useCurrentFrame();
  const header = useRiseIn(frame, 4, 20, 24);
  const binary = useScaleIn(frame, 26, 22);
  const scan = useScaleIn(frame, 56, 24);
  const fanOpacity = interpolate(frame, [84, 104], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 0 }}>
      {/* Header */}
      <div
        style={{
          ...header,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 18,
          marginBottom: 48,
        }}
      >
        <div
          style={{
            fontFamily: "'JetBrains Mono', ui-monospace, monospace",
            fontSize: 40,
            letterSpacing: 3,
            color: COLORS.blueBright,
            textTransform: "uppercase",
          }}
        >
          Safety model
        </div>
        <div style={{ fontSize: FONT.h2, fontWeight: 700, color: COLORS.textPrimary }}>
          Never executes untrusted code on the host
        </div>
      </div>

      {/* Binary input */}
      <div
        style={{
          ...binary,
          display: "flex",
          alignItems: "center",
          gap: 16,
          padding: "20px 48px",
          borderRadius: 18,
          background: "rgba(255,255,255,0.05)",
          border: `1px solid ${COLORS.cardBorder}`,
        }}
      >
        <span style={{ fontSize: 44 }}>📦</span>
        <span style={{ fontSize: 44, fontWeight: 700, color: COLORS.textPrimary }}>Binary</span>
      </div>

      {/* connector */}
      <Fan show={interpolate(frame, [40, 56], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" })} />

      {/* Risk scan node */}
      <div
        style={{
          ...scan,
          display: "flex",
          alignItems: "center",
          gap: 18,
          padding: "24px 56px",
          borderRadius: 22,
          background: `linear-gradient(120deg, ${COLORS.blue}22, ${COLORS.cyan}22)`,
          border: `1px solid ${COLORS.blueBright}55`,
        }}
      >
        <span style={{ fontSize: 48 }}>🛡️</span>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <span style={{ fontSize: 48, fontWeight: 800, color: COLORS.textPrimary }}>Risk Scan</span>
          <span style={{ fontSize: 30, color: COLORS.textMuted }}>capa + YARA + heuristics</span>
        </div>
      </div>

      {/* diverging connectors */}
      <div style={{ opacity: fanOpacity, display: "flex", justifyContent: "center", width: cardW * 3 + GAP * 2, marginTop: 8 }}>
        <div style={{ display: "flex", gap: GAP, justifyContent: "space-between", width: "100%", padding: "0 40px" }}>
          {RISKS.map((r) => (
            <div key={r.label} style={{ display: "flex", flexDirection: "column", alignItems: "center", width: cardW }}>
              <div style={{ width: 2, height: 40, background: r.color, opacity: 0.5 }} />
              <div
                style={{
                  width: 0,
                  height: 0,
                  borderLeft: "10px solid transparent",
                  borderRight: "10px solid transparent",
                  borderTop: `12px solid ${r.color}`,
                  opacity: 0.7,
                }}
              />
            </div>
          ))}
        </div>
      </div>

      {/* 3 risk tiers */}
      <div style={{ display: "flex", gap: GAP, marginTop: 10 }}>
        {RISKS.map((r, i) => {
          const start = 104 + i * 12;
          const rise = useRiseIn(frame, start, 22, 36);
          return (
            <div
              key={r.label}
              style={{
                opacity: rise.opacity,
                translate: `0px ${rise.translateY}px`,
                width: cardW,
                height: cardH,
                borderRadius: 26,
                padding: "36px 32px",
                background: r.bg,
                border: `1px solid ${r.color}66`,
                display: "flex",
                flexDirection: "column",
                gap: 18,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                <span
                  style={{
                    fontSize: 34,
                    fontWeight: 800,
                    color: r.color,
                    padding: "6px 22px",
                    borderRadius: 999,
                    background: `${r.color}22`,
                  }}
                >
                  {r.label}
                </span>
                {r.refuse && <span style={{ fontSize: 38 }}>🚫</span>}
              </div>
              <div style={{ fontSize: 46, fontWeight: 700, color: COLORS.textPrimary }}>{r.action}</div>
              <div style={{ fontSize: 30, color: COLORS.textMuted, lineHeight: 1.3, marginTop: "auto" }}>
                {r.detail}
              </div>
            </div>
          );
        })}
      </div>
    </AbsoluteFill>
  );
};

const Fan: React.FC<{ show: number }> = ({ show }) => (
  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", opacity: show, margin: "8px 0" }}>
    <div
      style={{
        width: 2,
        height: 36,
        background: `linear-gradient(180deg, ${COLORS.blue}00, ${COLORS.blueBright})`,
        scale: `1 ${show}`,
        transformOrigin: "top",
      }}
    />
    <div
      style={{
        width: 0,
        height: 0,
        borderLeft: "11px solid transparent",
        borderRight: "11px solid transparent",
        borderTop: `13px solid ${COLORS.blueBright}`,
        opacity: show,
      }}
    />
  </div>
);
