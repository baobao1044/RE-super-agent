import "./index.css";
import { AbsoluteFill, Sequence } from "remotion";
import { TransitionSeries, linearTiming } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { loadFont as loadInter } from "@remotion/google-fonts/Inter";
import { loadFont as loadMono } from "@remotion/google-fonts/JetBrainsMono";
import { SCENES } from "./theme";
import { Background } from "./components/Background";
import { Scene01Title } from "./scenes/Scene01Title";
import { Scene02Capabilities } from "./scenes/Scene02Capabilities";
import { Scene03Architecture } from "./scenes/Scene03Architecture";
import { Scene04Deobfuscation } from "./scenes/Scene04Deobfuscation";
import { Scene05Safety } from "./scenes/Scene05Safety";
import { Scene06Workflow } from "./scenes/Scene06Workflow";
import { Scene07CTA } from "./scenes/Scene07CTA";

// Load fonts once at module eval. Inter = primary sans, JetBrains Mono = code.
// Restrict to needed weights/subsets to avoid excessive network requests.
const inter = loadInter("normal", {
  weights: ["400", "500", "600", "700", "800"],
  subsets: ["latin"],
});
const mono = loadMono("normal", {
  weights: ["400", "500", "600", "700"],
  subsets: ["latin"],
});

if (typeof document !== "undefined") {
  document.documentElement.style.setProperty("--font-sans", `"${inter.fontFamily}"`);
  document.documentElement.style.setProperty("--font-mono", `"${mono.fontFamily}"`);
}

const fontFamily = `"${inter.fontFamily}", system-ui, -apple-system, sans-serif`;

// Scenes authored frame-0-relative to their own start. TransitionSeries resets
// useCurrentFrame() to each sequence's start, so inner animations key off 0.
const SCENE_LIST = [
  { key: "title", Comp: Scene01Title, duration: SCENES.title.duration },
  { key: "capabilities", Comp: Scene02Capabilities, duration: SCENES.capabilities.duration },
  { key: "architecture", Comp: Scene03Architecture, duration: SCENES.architecture.duration },
  { key: "deobfuscation", Comp: Scene04Deobfuscation, duration: SCENES.deobfuscation.duration },
  { key: "safety", Comp: Scene05Safety, duration: SCENES.safety.duration },
  { key: "workflow", Comp: Scene06Workflow, duration: SCENES.workflow.duration },
  { key: "cta", Comp: Scene07CTA, duration: SCENES.cta.duration },
];

const TRANSITION = 18; // 0.6s cross-fade between scenes

// Real timeline length: sum of scene durations minus the overlap of each transition.
export const TOTAL_DURATION =
  SCENE_LIST.reduce((acc, s) => acc + s.duration, 0) -
  (SCENE_LIST.length - 1) * TRANSITION;

// Build the flat TransitionSeries children: sequence, transition, sequence, ...
const children: React.ReactNode[] = [];
SCENE_LIST.forEach(({ key, Comp, duration }, i) => {
  children.push(
    <TransitionSeries.Sequence key={key} durationInFrames={duration}>
      {/* layout="none" lets the scene fill and position itself */}
      <Sequence durationInFrames={duration} layout="none">
        <Comp />
      </Sequence>
    </TransitionSeries.Sequence>
  );
  if (i < SCENE_LIST.length - 1) {
    children.push(
      <TransitionSeries.Transition
        key={`${key}-t`}
        presentation={fade()}
        timing={linearTiming({ durationInFrames: TRANSITION })}
      />
    );
  }
});

export const ReIntro: React.FC = () => {
  return (
    <AbsoluteFill style={{ fontFamily }}>
      <Background />
      <TransitionSeries>{children}</TransitionSeries>
    </AbsoluteFill>
  );
};
