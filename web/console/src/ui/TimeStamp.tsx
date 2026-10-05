import { timeView } from "./time.ts";
import "./ui.css";

type Props = {
  value: string | number | null | undefined;
  /** Compact: the relative phrase only, with both clocks on hover (for table cells). */
  compact?: boolean;
  empty?: string;
};

/**
 * Local time as the reading, UTC on hover, a relative phrase beside it. The relative phrase is
 * computed when the page renders and never ticks: the console does not refresh itself.
 */
export function TimeStamp({ value, compact = false, empty = "—" }: Props) {
  const view = timeView(value, Date.now());
  if (!view) return <span className="xs-time-empty">{empty}</span>;
  return (
    <time
      className="xs-time"
      dateTime={view.iso}
      title={compact ? `本地 ${view.local} · ${view.utc}` : view.utc}
    >
      {compact ? (
        view.relative
      ) : (
        <>
          <span>{view.local}</span> <span className="xs-time-rel">{view.relative}</span>
        </>
      )}
    </time>
  );
}
