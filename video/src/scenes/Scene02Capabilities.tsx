import { AbsoluteFill, useCurrentFrame, interpolate, Easing } from "remotion";
import { COLORS, FONT, EASE_OUT } from "../theme";
import { useRiseIn } from "../components/ui";

type Cap = { icon: string; title: string; desc: string; accent: string };

const CAPS: Cap[] = [
  {
    icon: "🛠️",
    title: "5 MCP servers",
    desc: "44 tools · Ghidra, radare2, angr, Frida, gdb, WinDbg, Qiling, capa, YARA, binwalk",
    accent: COLORS.blue,
  },
  {
    icon: "🧠",
    title: "5 Specialists",
    desc: "ReAct loop — reason → act → observe — over each domain's MCP tools",
    accent: COLORS.violet,
  },
  {
    icon: "🔄",
    title: "Adaptive workflow",
    desc: "LLM synthesizes a DAG per binary; self-adapts on anomalies",
    accent: COLORS.cyan,
  },
  {
    icon: "📚",
    title: "Playbook library",
    desc: "4 templates: crackme, packed_vm, malware, ctf — saved & reused",
    accent: COLORS.green,
  },
  {
    icon: "🛡️",
    title: "Safety layer",
    desc: "Risk scan → Docker sandbox / human confirm / static-only refusal",
    accent: COLORS.blueBright,
  },
  {
    icon: "🐍",
    title: "Python deobfuscation",
    desc: "Safe static RE → agentic LLM decompiler recovers real source",
    accent: COLORS.violetBright,
  },
];

// Scene 2 — Six capability cards revealed in a 3×2 grid with a stagger.
export const Scene02Capabilities: React.FC = () => {
  const frame = useCurrentFrame();
  const header = useRiseIn(frame, 4, 20, 24);

  const COLS = 3;
  const GAP = 36;
  const cardW = 540;
  const cardH = 300;

  return (
    <AbsoluteFill
      style={{
        alignItems: "center",
        justifyContent: "center",
        flexDirection: "column",
        gap: 56,
      }}
    >
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
            color: COLORS.blueBright,
            textTransform: "uppercase",
          }}
        >
          Capabilities
        </div>
        <div style={{ fontSize: FONT.h2, fontWeight: 700, color: COLORS.textPrimary }}>
          Six pillars of the hybrid architecture
        </div>
      </div>

      {/* Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: `repeat(${COLS}, ${cardW}px)`,
          gridAutoRows: cardH,
          gap: GAP,
        }}
      >
        {CAPS.map((cap, i) => {
          const start = 26 + i * 10; // stagger
          const rise = useRiseIn(frame, start, 20, 40);
          const opacity = rise.opacity;
          const translateY = rise.translateY;

          return (
            <div
              key={cap.title}
              style={{
                opacity,
                translate: `0px ${translateY}px`,
                width: cardW,
                height: cardH,
                borderRadius: 28,
                padding: "44px 40px",
                background: COLORS.cardBg,
                border: `1px solid ${COLORS.cardBorder}`,
                boxShadow: `0 20px 60px -20px ${cap.accent}22, inset 0 1px 0 rgba(255,255,255,0.06)`,
                display: "flex",
                flexDirection: "column",
                gap: 22,
                backdropFilter: "blur(4px)",
              }}
            >
              <div style={{ fontSize: 84, lineHeight: 1 }}>{cap.icon}</div>
              <div
                style={{
                  fontSize: 50,
                  fontWeight: 700,
                  color: COLORS.textPrimary,
                  lineHeight: 1.05,
                }}
              >
                {cap.title}
              </div>
              <div
                style={{
                  fontSize: 33,
                  color: COLORS.textMuted,
                  lineHeight: 1.35,
                }}
              >
                {cap.desc}
              </div>
              {/* accent bar */}
              <div
                style={{
                  marginTop: "auto",
                  height: 5,
                  width: interpolate(frame, [start + 14, start + 30], [0, 96], {
                    extrapolateLeft: "clamp",
                    extrapolateRight: "clamp",
                    easing: Easing.bezier(...EASE_OUT),
                  }),
                  borderRadius: 999,
                  background: cap.accent,
                }}
              />
            </div>
          );
        })}
      </div>
    </AbsoluteFill>
  );
};
