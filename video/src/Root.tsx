import "./index.css";
import { Composition } from "remotion";
import { ReIntro, TOTAL_DURATION } from "./Composition";

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="ReIntro"
        component={ReIntro}
        // TransitionSeries overlaps each cross-fade, so the real timeline is
        // sum(scene durations) - (num_transitions * transition_duration).
        durationInFrames={TOTAL_DURATION}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
