import { AbsoluteFill, useCurrentFrame, interpolate, Easing } from "remotion";
import { COLORS, FONT, EASE_OUT } from "../theme";
import { useRiseIn, useScaleIn } from "../components/ui";

type Node = {
  label: string;
  sub: string;
  tools: string;
  accent: string;
};

const SPECIALISTS: Node[] = [
  { label: "Static", sub: "Ghidra + r2 + capstone", tools: "8 tools", accent: COLORS.blue },
  { label: "Dynamic", sub: "Frida + gdb + WinDbg", tools: "16 tools", accent: COLORS.violet },
  { label: "Symbolic", sub: "angr + brute solver", tools: "5 tools", accent: COLORS.cyan },
  { label: "Deobfuscation", sub: "Qiling + VM + LLM lifter", tools: "9 tools", accent: COLORS.green },
  { label: "Malware", sub: "capa + YARA + binwalk", tools: "6 tools", accent: COLORS.blueBright },
];

const cardW = 300;
const cardH = 320;
const GAP = 30;
const totalRowW = SPECIALISTS.length * cardW + (SPECIALISTS.length - 1) * GAP;

// Scene 3 — Architecture mindmap: CLI → Supervisor → 5 Specialists (with MCP).
export const Scene03Architecture: React.FC = () => {
  const frame = useCurrentFrame();
  const header = useRiseIn(frame, 4, 20, 24);

  // Tiers animate in sequence: CLI → Supervisor → Specialists.
  const cli = useScaleIn(frame, 22, 22);
  const arrow1 = interpolate(frame, [44, 60], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });
  const sup = useScaleIn(frame, 52, 24);
  const arrow2 = interpolate(frame, [74, 90], [0, 1], {
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
          marginBottom: 60,
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
          Architecture
        </div>
        <div style={{ fontSize: FONT.h2, fontWeight: 700, color: COLORS.textPrimary }}>
          A supervisor orchestrates five specialists
        </div>
      </div>

      {/* Tier 1: CLI */}
      <div
        style={{
          ...cli,
          display: "flex",
          alignItems: "center",
          gap: 16,
          padding: "24px 56px",
          borderRadius: 20,
          background: "rgba(59,130,246,0.12)",
          border: `1px solid ${COLORS.cardBorderAccent}`,
        }}
      >
        <span style={{ fontSize: 52 }}>⌨️</span>
        <span style={{ fontSize: 52, fontWeight: 700, color: COLORS.textPrimary }}>
          re-agent CLI
        </span>
        <span
          style={{
            fontFamily: "'JetBrains Mono', ui-monospace, monospace",
            fontSize: 32,
            color: COLORS.textMuted,
            marginLeft: 12,
          }}
        >
          one-shot · REPL · --json · --trace
        </span>
      </div>

      {/* Arrow 1 */}
      <Connector show={arrow1} />

      {/* Tier 2: Supervisor */}
      <div
        style={{
          ...sup,
          display: "flex",
          alignItems: "center",
          gap: 18,
          padding: "28px 64px",
          borderRadius: 24,
          background: `linear-gradient(120deg, ${COLORS.violet}22, ${COLORS.blue}22)`,
          border: `1px solid ${COLORS.violet}55`,
          boxShadow: `0 20px 60px -20px ${COLORS.violet}44`,
        }}
      >
        <span style={{ fontSize: 56 }}>🎛️</span>
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <span style={{ fontSize: 56, fontWeight: 800, color: COLORS.textPrimary }}>Supervisor</span>
          <span style={{ fontSize: 34, color: COLORS.textMuted }}>
            analyze → risk scan → synth DAG → adaptive execute → report
          </span>
        </div>
      </div>

      {/* Arrow 2 */}
      <Connector show={arrow2} />

      {/* Tier 3: Specialists row */}
      <div
        style={{
          display: "flex",
          gap: GAP,
          width: totalRowW,
          justifyContent: "center",
        }}
      >
        {SPECIALISTS.map((s, i) => {
          const start = 96 + i * 10;
          const rise = useRiseIn(frame, start, 20, 50);
          return (
            <div
              key={s.label}
              style={{
                opacity: rise.opacity,
                translate: `0px ${rise.translateY}px`,
                width: cardW,
                height: cardH,
                borderRadius: 26,
                padding: "36px 28px",
                background: COLORS.cardBg,
                border: `1px solid ${COLORS.cardBorder}`,
                display: "flex",
                flexDirection: "column",
                gap: 18,
                boxShadow: `0 16px 48px -24px ${s.accent}33`,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ fontSize: 44, fontWeight: 700, color: s.accent }}>{s.label}</span>
                <span
                  style={{
                    fontFamily: "'JetBrains Mono', ui-monospace, monospace",
                    fontSize: 26,
                    color: COLORS.textDim,
                    padding: "6px 14px",
                    borderRadius: 999,
                    background: "rgba(255,255,255,0.06)",
                  }}
                >
                  {s.tools}
                </span>
              </div>
              <div style={{ fontSize: 32, color: COLORS.textMuted, lineHeight: 1.3 }}>{s.sub}</div>
              <div
                style={{
                  marginTop: "auto",
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  fontFamily: "'JetBrains Mono', ui-monospace, monospace",
                  fontSize: 30,
                  color: s.accent,
                  opacity: 0.85,
                }}
              >
                <span style={{ display: "inline-block", width: 10, height: 10, borderRadius: 999, background: s.accent }} />
                MCP server
              </div>
            </div>
          );
        })}
      </div>
    </AbsoluteFill>
  );
};

// A vertical connector line + arrowhead that grows downward.
const Connector: React.FC<{ show: number }> = ({ show }) => (
  <div
    style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      opacity: show,
      margin: "18px 0",
    }}
  >
    <div
      style={{
        width: 2,
        height: 56,
        background: `linear-gradient(180deg, ${COLORS.blue}00, ${COLORS.blueBright})`,
        scale: `1 ${show}`,
        transformOrigin: "top",
      }}
    />
    <div
      style={{
        width: 0,
        height: 0,
        borderLeft: "12px solid transparent",
        borderRight: "12px solid transparent",
        borderTop: `14px solid ${COLORS.blueBright}`,
        opacity: show,
      }}
    />
  </div>
);
