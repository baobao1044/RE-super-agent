import { AbsoluteFill, useCurrentFrame } from "remotion";
import { COLORS, FONT } from "../theme";
import { useRiseIn, useScaleIn } from "../components/ui";

// Scene 7 — Call to action: install, run, GitHub, license.
export const Scene07CTA: React.FC = () => {
  const frame = useCurrentFrame();
  const title = useScaleIn(frame, 4, 24);
  const cmd1 = useRiseIn(frame, 30, 20, 24);
  const cmd2 = useRiseIn(frame, 48, 20, 24);
  const repo = useRiseIn(frame, 70, 20, 24);
  const foot = useRiseIn(frame, 96, 20, 24);

  const gradient = `linear-gradient(110deg, ${COLORS.blueBright} 0%, ${COLORS.violetBright} 100%)`;

  // Blinking cursor on the run command.
  const cursorOn = Math.floor((frame / 8) % 2) === 0;

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 40 }}>
        {/* Title */}
        <div style={{ ...title, display: "flex", flexDirection: "column", alignItems: "center", gap: 16 }}>
          <div
            style={{
              fontSize: FONT.display,
              fontWeight: 800,
              letterSpacing: -2,
              lineHeight: 1,
              background: gradient,
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              color: "transparent",
            }}
          >
            Try RE-super-agent
          </div>
        </div>

        {/* Install command */}
        <CmdLine {...cmd1} prompt="$" text="pip install -e ." />

        {/* Run command with blinking cursor */}
        <CmdLine
          {...cmd2}
          prompt="$"
          text={`re-agent ./crackme.elf "bypass the license check"`}
          cursor={cursorOn}
        />

        {/* GitHub repo */}
        <div
          style={{
            ...repo,
            display: "flex",
            alignItems: "center",
            gap: 18,
            padding: "20px 40px",
            borderRadius: 18,
            background: "rgba(255,255,255,0.05)",
            border: `1px solid ${COLORS.cardBorder}`,
          }}
        >
          <span style={{ fontSize: 48 }}>🐙</span>
          <span
            style={{
              fontFamily: "'JetBrains Mono', ui-monospace, monospace",
              fontSize: 44,
              fontWeight: 600,
              color: COLORS.blueBright,
            }}
          >
            github.com/baobao1044/RE-super-agent
          </span>
        </div>

        {/* Footer note */}
        <div
          style={{
            ...foot,
            display: "flex",
            alignItems: "center",
            gap: 24,
            fontSize: 34,
            color: COLORS.textMuted,
          }}
        >
          <span style={{ color: COLORS.textPrimary, fontWeight: 600 }}>MIT license</span>
          <span style={{ color: COLORS.textDim }}>·</span>
          <span>For research, CTF & authorized malware analysis only</span>
        </div>
      </div>
    </AbsoluteFill>
  );
};

const CmdLine: React.FC<{
  prompt: string;
  text: string;
  cursor?: boolean;
  opacity?: number;
  translateY?: number;
}> = ({ prompt, text, cursor, opacity = 1, translateY = 0 }) => (
  <div
    style={{
      opacity,
      translate: `0px ${translateY}px`,
      display: "flex",
      alignItems: "center",
      gap: 18,
      padding: "22px 36px",
      borderRadius: 16,
      background: "rgba(0,0,0,0.4)",
      border: `1px solid ${COLORS.cardBorder}`,
      fontFamily: "'JetBrains Mono', ui-monospace, monospace",
      fontSize: 44,
      whiteSpace: "nowrap",
    }}
  >
    <span style={{ color: COLORS.green, fontWeight: 700 }}>{prompt}</span>
    <span style={{ color: COLORS.textPrimary }}>{text}</span>
    {cursor && (
      <span
        style={{
          display: "inline-block",
          width: 20,
          height: 40,
          background: COLORS.violetBright,
          marginLeft: 4,
        }}
      />
    )}
  </div>
);
