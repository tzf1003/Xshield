// The custom time range (docs/06 6.3.2). Bounds are local time; the window must be ordered, at most
// seven days, and inside the retention period.

import { Modal } from "antd";
import { useEffect, useState } from "react";
import { fromLocalInput, toLocalInput } from "../lib/local-time.ts";
import { validCustom } from "../lib/time-range.ts";
import { useSetSearch } from "./scope.ts";

const DAY_MS = 24 * 60 * 60 * 1000;

type Props = {
  open: boolean;
  onClose: () => void;
};

export function RangeDialog({ open, onClose }: Props) {
  const setSearch = useSetSearch();
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const now = Date.now();
    setUntil(toLocalInput(now));
    setSince(toLocalInput(now - DAY_MS));
    setError(null);
  }, [open]);

  const apply = () => {
    const from = fromLocalInput(since);
    const to = fromLocalInput(until);
    if (from === null || to === null) {
      setError("请选择开始和结束时间");
      return;
    }
    if (!validCustom(from, to, Date.now())) {
      setError("开始要早于结束，两者相隔最长 7 天，且不早于保留期");
      return;
    }
    setSearch({ range: "custom", since: from, until: to });
    onClose();
  };

  return (
    <Modal
      open={open}
      title="自定义时间范围"
      okText="应用"
      cancelText="取消"
      onOk={apply}
      onCancel={onClose}
    >
      <div className="stack">
        <label className="field">
          <span className="field-label">开始</span>
          <input
            className="native-input"
            type="datetime-local"
            value={since}
            onChange={(event) => setSince(event.target.value)}
          />
        </label>
        <label className="field">
          <span className="field-label">结束</span>
          <input
            className="native-input"
            type="datetime-local"
            value={until}
            onChange={(event) => setUntil(event.target.value)}
          />
        </label>
        {error ? <div className="field-error">{error}</div> : null}
        <div className="field-help">时间按本地时区。最长 7 天，这是网关日志的保留期。</div>
      </div>
    </Modal>
  );
}
