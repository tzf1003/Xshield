// The YAML / JSON view of a site configuration (docs/06 6.4.9): CodeMirror with line numbers, highlighting and
// error markers. It edits the same draft as the form: every text that parses becomes the draft; a text that
// does not parse keeps the last good draft and says where the error is. Loaded lazily (see yaml-lazy.tsx).

import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { json } from "@codemirror/lang-json";
import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { type Diagnostic, lintGutter, setDiagnostics } from "@codemirror/lint";
import { EditorState } from "@codemirror/state";
import { EditorView, highlightActiveLine, keymap, lineNumbers } from "@codemirror/view";
import { tags } from "@lezer/highlight";
import { Segmented } from "antd";
import { useEffect, useRef, useState } from "react";
import type { SiteSpec } from "../../api/types.ts";
import { specToJson, specToYaml } from "../../lib/yaml.ts";
import { type SpecText, parseSpecText } from "./spec-model.ts";

export type YamlFormat = "yaml" | "json";

type Failure = Extract<SpecText, { ok: false }>;

/**
 * Token colours from the console's own tokens (docs/06 6.5.2). CodeMirror's default style was picked
 * for a light page and fails 4.5:1 on the dark one, so the tokens here are the ones that pass in both.
 */
const HIGHLIGHT = HighlightStyle.define([
  { tag: tags.propertyName, color: "var(--accent)" },
  { tag: [tags.comment, tags.meta], color: "var(--ink-2)" },
  {
    tag: [tags.punctuation, tags.string, tags.number, tags.bool, tags.null, tags.keyword],
    color: "var(--ink)",
  },
]);

/** The active line keeps the page's own surface tint, so the text on it keeps its contrast. */
const ACTIVE_LINE = EditorView.theme({
  ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "var(--sunken)" },
});

function CodeHost({
  initialText,
  format,
  failure,
  onText,
}: {
  initialText: string;
  format: YamlFormat;
  failure: Failure | null;
  onText: (text: string) => void;
}) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onTextRef = useRef(onText);
  useEffect(() => {
    onTextRef.current = onText;
  });

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return undefined;
    const language = format === "json" ? json() : yaml();
    const view = new EditorView({
      parent: host,
      state: EditorState.create({
        doc: initialText,
        extensions: [
          lineNumbers(),
          highlightActiveLine(),
          history(),
          keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
          syntaxHighlighting(HIGHLIGHT, { fallback: true }),
          ACTIVE_LINE,
          lintGutter(),
          language,
          EditorView.lineWrapping,
          EditorView.contentAttributes.of({ "aria-label": "站点配置，YAML 或 JSON" }),
          EditorView.updateListener.of((update) => {
            if (update.docChanged) onTextRef.current(update.state.doc.toString());
          }),
        ],
      }),
    });
    viewRef.current = view;
    return () => {
      view.destroy();
      viewRef.current = null;
    };
  }, [initialText, format]);

  // Marks the line of a parse error; the column, when known, starts the mark.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const doc = view.state.doc;
    const diagnostics: Diagnostic[] = [];
    if (failure && failure.line !== null) {
      const lineNumber = Math.min(Math.max(1, failure.line), doc.lines);
      const line = doc.line(lineNumber);
      const from = failure.column ? Math.min(line.from + failure.column - 1, line.to) : line.from;
      diagnostics.push({ from, to: line.to, severity: "error", message: failure.message });
    }
    view.dispatch(setDiagnostics(view.state, diagnostics));
  }, [failure]);

  return <div ref={hostRef} className="cm-host" />;
}

/**
 * The text view. `spec` is the current draft: switching the format converts it, which is only offered when
 * the text in the editor parses. `onParsed` receives every parse result.
 */
export function YamlEditor({
  spec,
  onParsed,
}: {
  spec: SiteSpec;
  onParsed: (result: SpecText) => void;
}) {
  const [format, setFormat] = useState<YamlFormat>("yaml");
  const [epoch, setEpoch] = useState(0);
  const [initialText, setInitialText] = useState(() => specToYaml(spec));
  const [failure, setFailure] = useState<Failure | null>(null);
  const [lastOk, setLastOk] = useState(true);
  const onParsedRef = useRef(onParsed);
  useEffect(() => {
    onParsedRef.current = onParsed;
  });

  const handleText = (text: string) => {
    const result = parseSpecText(text);
    setLastOk(result.ok);
    setFailure(result.ok ? null : result);
    onParsedRef.current(result);
  };

  const switchFormat = (next: YamlFormat) => {
    if (!lastOk || next === format) return;
    setFormat(next);
    setInitialText(next === "json" ? specToJson(spec) : specToYaml(spec));
    setFailure(null);
    setLastOk(true);
    setEpoch((value) => value + 1);
  };

  return (
    <div className="stack-tight">
      <div className="row between">
        <Segmented
          value={format}
          options={[
            { label: "YAML", value: "yaml" },
            { label: "JSON", value: "json" },
          ]}
          onChange={(value) => switchFormat(value === "json" ? "json" : "yaml")}
        />
        <span className="small muted">
          YAML 只是编辑格式，保存的是 JSON，注释不会保留。
          {lastOk ? "" : " 修好错误后才能切换格式。"}
        </span>
      </div>
      <CodeHost
        key={epoch}
        initialText={initialText}
        format={format}
        failure={failure}
        onText={handleText}
      />
      <div className={failure ? "field-error" : "small"} role="status" aria-live="polite">
        {failure ? failure.message : "解析正常，改动已进入草稿。"}
      </div>
    </div>
  );
}
