import { Input } from "antd";
import { useState } from "react";
import { normalizePaste } from "../../shell/palette-classifier.ts";
import "./identity.css";
import "./investigation.css";

type Props = {
  /** Accessible name and visible hint noun, for example 模型调用 ID. */
  label: string;
  /** The ID prefix shown as the placeholder, for example `mdl_`. */
  prefix: string;
  pattern: RegExp;
  /** The ID that is open now; the box starts with it. */
  current?: string;
  onOpen: (id: string) => void;
  /** Same ID asked again: read it again instead of navigating to where we already are. */
  onRepeat?: () => void;
  buttonText?: string;
};

/**
 * An exact-ID box. Nothing is sent for text that is not a canonical ID, and a pasted ID loses the
 * quotes and spaces it arrived with. Opening is an explicit press, never a side effect of typing.
 */
export function IdLookup({
  label,
  prefix,
  pattern,
  current,
  onOpen,
  onRepeat,
  buttonText = "查询",
}: Props) {
  const [value, setValue] = useState(current ?? "");
  const [problem, setProblem] = useState<string | null>(null);

  function submit() {
    const id = normalizePaste(value);
    if (!pattern.test(id)) {
      setProblem(`请输入规范的${label}（${prefix}加小写 UUIDv7）。`);
      return;
    }
    setProblem(null);
    setValue(id);
    if (id === current && onRepeat) onRepeat();
    else onOpen(id);
  }

  return (
    <div className="xs-lookup">
      <Input.Search
        aria-label={label}
        placeholder={`${prefix}…`}
        enterButton={buttonText}
        value={value}
        status={problem ? "error" : undefined}
        maxLength={64}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => {
          setValue(event.target.value);
          setProblem(null);
        }}
        onSearch={submit}
      />
      {problem ? <p className="xs-field-error">{problem}</p> : null}
    </div>
  );
}
