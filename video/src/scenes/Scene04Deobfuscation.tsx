import { AbsoluteFill, useCurrentFrame, interpolate, Easing } from "remotion";
import { COLORS, FONT, EASE_OUT } from "../theme";
import { Mono, useRiseIn, useScaleIn } from "../components/ui";

// Scene 4 — Python deobfuscation pipeline (safe static, agentic LLM decompiler).
export const Scene04Deobfuscation: React.FC = () => {
  const frame = useCurrentFrame();
  const header = useRiseIn(frame, 4, 20, 24);
  const badge = useScaleIn(frame, 26, 22);

  // Pipeline steps (vertical column on the left).
  const steps = [
    { tag: "1", label: "extract_payload_blob()", note: "parse _B['p'] · AST, no exec" },
    { tag: "2", label: "lzma.decompress(b64decode)", note: "decompress payload" },
    { tag: "3", label: "custom deserializer", note: "reconstruct code object · no exec" },
  ];

  // 3 outputs (row on the right).
  const outputs = [
    { name: "recover_python_source", desc: "structural summary", accent: COLORS.textMuted, hl: false },
    { name: "decompile_python_source", desc: "signatures + bytecode", accent: COLORS.blue, hl: false },
    { name: "decompile_python_source_llm", desc: "real if/for/try-except", accent: COLORS.violetBright, hl: true },
  ];

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", flexDirection: "column", gap: 44 }}>
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
          Python deobfuscation
        </div>
        <div style={{ fontSize: FONT.h2, fontWeight: 700, color: COLORS.textPrimary }}>
          Safe static RE — never executes the protected code
        </div>
      </div>

      {/* Protection scheme badge */}
      <div
        style={{
          ...badge,
          display: "flex",
          alignItems: "center",
          gap: 16,
          padding: "18px 36px",
          borderRadius: 999,
          background: "rgba(139,92,255,0.12)",
          border: `1px solid ${COLORS.violet}55`,
        }}
      >
        <span style={{ fontSize: 36 }}>🔐</span>
        <span style={{ fontSize: 36, color: COLORS.textMuted }}>
          <Mono color={COLORS.violetBright}>enphysic.pro / Ngocuyencoder</Mono> ·{" "}
          <Mono color={COLORS.textMuted}>base64 → LZMA → custom marshal → 4 blobs → CJK names</Mono>
        </span>
      </div>

      {/* Main two-column area */}
      <div style={{ display: "flex", gap: 56, alignItems: "center" }}>
        {/* Left: vertical pipeline */}
        <div style={{ display: "flex", flexDirection: "column", gap: 22, width: 620 }}>
          {/* Input file chip */}
          <PipelineInput frame={frame} start={46} />

          {steps.map((s, i) => (
            <PipelineStep key={s.label} tag={s.tag} label={s.label} note={s.note} start={62 + i * 16} />
          ))}
        </div>

        {/* Right: 3 outputs + highlight */}
        <div style={{ display: "flex", flexDirection: "column", gap: 26, width: 760 }}>
          {outputs.map((o, i) => (
            <OutputCard key={o.name} {...o} start={120 + i * 14} frame={frame} />
          ))}

          {/* Before/after snippet for the LLM output */}
          <SnippetReveal frame={frame} start={170} />
        </div>
      </div>
    </AbsoluteFill>
  );
};

const PipelineInput: React.FC<{ frame: number; start: number }> = ({ frame, start }) => {
  const rise = useRiseIn(frame, start, 18, 24);
  return (
    <div
      style={{
        ...rise,
        display: "flex",
        alignItems: "center",
        gap: 16,
        padding: "22px 30px",
        borderRadius: 18,
        background: "rgba(255,255,255,0.05)",
        border: `1px solid ${COLORS.cardBorder}`,
      }}
    >
      <span style={{ fontSize: 40 }}>📄</span>
      <span style={{ fontSize: 40, fontWeight: 700, color: COLORS.textPrimary }}>Protected .py</span>
    </div>
  );
};

const PipelineStep: React.FC<{ tag: string; label: string; note: string; start: number }> = ({
  tag,
  label,
  note,
  start,
}) => {
  const frame = useCurrentFrame();
  const rise = useRiseIn(frame, start, 18, 24);
  return (
    <div style={{ ...rise, display: "flex", gap: 18, alignItems: "center" }}>
      <div
        style={{
          width: 56,
          height: 56,
          borderRadius: 999,
          background: COLORS.blue,
          color: "#fff",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 34,
          fontWeight: 700,
          flexShrink: 0,
        }}
      >
        {tag}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <span style={{ fontSize: 36, fontWeight: 600, color: COLORS.cyan }}>
          <Mono color={COLORS.cyan}>{label}</Mono>
        </span>
        <span style={{ fontSize: 30, color: COLORS.textMuted }}>{note}</span>
      </div>
    </div>
  );
};

const OutputCard: React.FC<{
  name: string;
  desc: string;
  accent: string;
  hl: boolean;
  start: number;
  frame: number;
}> = ({ name, desc, accent, hl, start, frame }) => {
  const rise = useRiseIn(frame, start, 18, 28);
  const glowPulse = hl
    ? interpolate(frame, [start + 20, start + 40], [0.4, 0.7], {
        extrapolateLeft: "clamp",
        extrapolateRight: "extend",
        easing: Easing.bezier(...EASE_OUT),
      })
    : 0;
  return (
    <div
      style={{
        ...rise,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "22px 30px",
        borderRadius: 18,
        background: hl ? "rgba(139,92,255,0.14)" : "rgba(255,255,255,0.04)",
        border: hl ? `1px solid ${accent}aa` : `1px solid ${COLORS.cardBorder}`,
        boxShadow: hl ? `0 16px 50px -16px ${accent}${Math.round(glowPulse * 99)}` : "none",
      }}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <span style={{ fontSize: 38, fontWeight: 600 }}>
          <Mono color={accent}>{name}()</Mono>
        </span>
        <span style={{ fontSize: 30, color: COLORS.textMuted }}>{desc}</span>
      </div>
      {hl && (
        <span
          style={{
            fontSize: 28,
            fontWeight: 700,
            color: accent,
            padding: "8px 18px",
            borderRadius: 999,
            background: "rgba(139,92,255,0.18)",
          }}
        >
          ⭐ real source
        </span>
      )}
    </div>
  );
};

// Before/after snippet — bytecode comments → real Python.
const SnippetReveal: React.FC<{ frame: number; start: number }> = ({ frame, start }) => {
  const rise = useRiseIn(frame, start, 22, 28);
  // arrow + after appear slightly later
  const arrowOp = interpolate(frame, [start + 18, start + 30], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(...EASE_OUT),
  });
  const after = useRiseIn(frame, start + 24, 22, 20);

  return (
    <div
      style={{
        ...rise,
        display: "flex",
        alignItems: "center",
        gap: 20,
        padding: "22px 26px",
        borderRadius: 18,
        background: "rgba(0,0,0,0.32)",
        border: `1px solid ${COLORS.cardBorder}`,
      }}
    >
      {/* before */}
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <span style={{ fontSize: 26, color: COLORS.textDim, marginBottom: 4 }}>bytecode</span>
        <Mono color={COLORS.textMuted}>
          <span style={{ fontSize: 30 }}>{`# POP_JUMP_FORWARD_IF_FALSE`}</span>
        </Mono>
      </div>
      {/* arrow */}
      <div style={{ opacity: arrowOp, fontSize: 40, color: COLORS.violetBright }}>→</div>
      {/* after */}
      <div style={{ ...after, display: "flex", flexDirection: "column", gap: 4 }}>
        <span style={{ fontSize: 26, color: COLORS.violetBright, marginBottom: 4 }}>real Python</span>
        <Mono color={COLORS.violetBright}>
          <span style={{ fontSize: 32, fontWeight: 700 }}>if x in y:</span>
        </Mono>
      </div>
    </div>
  );
};
