import { SearchOutlined } from "@ant-design/icons";
import { Input, type InputRef, Modal } from "antd";
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { type PaletteResult, paletteSearch } from "./palette-classifier.ts";

type Props = {
  open: boolean;
  onClose: () => void;
  roles: readonly string[] | null;
  siteId: string | null;
  onRun: (result: PaletteResult) => void;
};

/**
 * Command palette: paste an ID to open it, or type to find a page. Results never include what
 * the operator's roles hide from the navigation. Combobox pattern: focus stays in the input,
 * arrow keys move the highlighted option, Enter runs it, Esc closes.
 */
export function CommandPalette({ open, onClose, roles, siteId, onRun }: Props) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<InputRef>(null);
  const outcome = useMemo(() => paletteSearch(query, roles, siteId), [query, roles, siteId]);
  const { results } = outcome;
  const clamped = Math.min(active, Math.max(results.length - 1, 0));

  useEffect(() => {
    void clamped;
    document.getElementById(`palette-option-${clamped}`)?.scrollIntoView?.({ block: "nearest" });
  }, [clamped]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  function run(result: PaletteResult | undefined) {
    if (!result) return;
    onClose();
    onRun(result);
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (results.length === 0) return;
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActive((clamped + step + results.length) % results.length);
    } else if (event.key === "Enter") {
      event.preventDefault();
      run(results[clamped]);
    }
  }

  const listId = "command-palette-results";
  let lastGroup: string | null = null;
  return (
    <Modal
      open={open}
      onCancel={onClose}
      footer={null}
      closable={false}
      width={640}
      destroyOnHidden
      centered={false}
      className="xs-palette"
      title={<span className="xs-visually-hidden">命令面板</span>}
      styles={{ header: { display: "none" }, body: { padding: 0 } }}
      afterOpenChange={(visible) => {
        if (visible) input.current?.focus();
      }}
    >
      <Input
        ref={input}
        size="large"
        variant="borderless"
        prefix={<SearchOutlined />}
        placeholder="输入页面名称，或粘贴请求 / 模型 / 案件等对象 ID"
        value={query}
        onChange={(event) => {
          setQuery(event.target.value);
          setActive(0);
        }}
        onKeyDown={onKeyDown}
        autoComplete="off"
        spellCheck={false}
        maxLength={256}
        role="combobox"
        aria-label="命令面板"
        aria-expanded={results.length > 0}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={results.length > 0 ? `palette-option-${clamped}` : undefined}
      />
      {outcome.notice && <p className="xs-palette-notice">{outcome.notice}</p>}
      <div
        id={listId}
        role="listbox"
        aria-label="命令面板结果"
        className="xs-palette-list"
        // A scroll container would otherwise become a keyboard tab stop of its own.
        tabIndex={-1}
      >
        {results.map((result, index) => {
          const heading = result.group === lastGroup ? null : result.group;
          lastGroup = result.group;
          return (
            <div key={result.id} role="presentation">
              {heading && (
                <div className="xs-palette-group" aria-hidden="true">
                  {heading === "object" ? "跳转到对象" : "页面"}
                </div>
              )}
              <button
                type="button"
                role="option"
                id={`palette-option-${index}`}
                aria-selected={index === clamped}
                tabIndex={-1}
                className={index === clamped ? "xs-palette-option is-active" : "xs-palette-option"}
                onMouseMove={() => setActive(index)}
                onClick={() => run(result)}
              >
                <span className="xs-palette-label">{result.label}</span>
                <span className="xs-palette-hint">{result.hint}</span>
              </button>
            </div>
          );
        })}
      </div>
      {results.length === 0 && !outcome.notice && (
        <p className="xs-palette-empty">没有匹配的页面或对象。</p>
      )}
    </Modal>
  );
}
