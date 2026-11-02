// Rewrites the synonym groups of a site as field declarations (console design 3.4). For each group, the positions its
// words reach in the latest records are listed; each one gets the class it goes to and the interfaces it is limited
// to. Applying adds the declarations to the draft and removes the groups, so the save dialog shows the whole change.

import { Modal } from "antd";
import { useState } from "react";
import { useSiteObjects } from "../../../api/queries.ts";
import type { FieldKindDeclaration, ObjectSlotRow, SiteSpec } from "../../../api/types.ts";
import { checkDeclarations, declarationKey, kindKey } from "../../../lib/objects-validate.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { Empty, ErrorBar, Loading } from "../../../ui/Page.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { fieldOfKey, migrateSynonyms, pathWordWarnings, scopeOfKey } from "./objects-model.ts";

type Pair = readonly [string, string];
type Choice = { kind: string; scope: "only" | "all" };

type Props = {
  site: string;
  working: SiteSpec;
  onClose: () => void;
  onApply: (spec: SiteSpec) => void;
};

/** The words of a field name: `paymentId` and `payment_id` both read as `payment`, `id`. */
function wordsOf(field: string): string[] {
  return field
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[_-]+/)
    .filter((part) => part.length > 0);
}

/** Whether one of the field's words is the synonym word, with a trailing `s` not counting. */
function wordIn(field: string, word: string): boolean {
  const target = kindKey(word);
  return wordsOf(field).some((part) => kindKey(part) === target);
}

/**
 * The class a position goes to by default: the word its class already is, else the word the field does not
 * carry (the other word of the group is the class it names). Limited to the interface of its evidence.
 */
function defaultChoice(row: ObjectSlotRow, pair: Pair): Choice {
  const [a, b] = pair;
  const field = fieldOfKey(row.key) ?? "";
  let kind = b;
  if (row.class !== null && kindKey(row.class) === kindKey(a)) kind = a;
  else if (row.class !== null && kindKey(row.class) === kindKey(b)) kind = b;
  else if (wordIn(field, a) && !wordIn(field, b)) kind = b;
  else if (wordIn(field, b) && !wordIn(field, a)) kind = a;
  return { kind, scope: "only" };
}

export function SynonymMigrateDialog({ site, working, onClose, onApply }: Props) {
  const objects = useSiteObjects(site);
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const pairs: Pair[] = working.advanced?.synonyms ?? [];
  const data = objects.data;

  const choiceKey = (pair: Pair, row: ObjectSlotRow) => `${pair[0]}|${pair[1]}|${row.id}`;
  const choiceOf = (pair: Pair, row: ObjectSlotRow): Choice =>
    choices[choiceKey(pair, row)] ?? defaultChoice(row, pair);
  const change = (pair: Pair, row: ObjectSlotRow, patch: Partial<Choice>) => {
    const next = { ...choiceOf(pair, row), ...patch };
    setChoices((previous) => ({ ...previous, [choiceKey(pair, row)]: next }));
  };

  // The declarations the groups become, one per position the groups reach; a repeated one is written once.
  const plan = pairs.map((pair) => {
    const affected = (data?.slots ?? []).filter((row) => {
      const field = fieldOfKey(row.key);
      return field !== null && (wordIn(field, pair[0]) || wordIn(field, pair[1]));
    });
    return { pair, affected };
  });
  const declarations: FieldKindDeclaration[] = [];
  for (const item of plan) {
    for (const row of item.affected) {
      const field = fieldOfKey(row.key);
      if (field === null) continue;
      const choice = choiceOf(item.pair, row);
      const kind = choice.kind.toLowerCase();
      declarations.push(
        choice.scope === "only" ? { field, kind, in: [scopeOfKey(row.key)] } : { field, kind },
      );
    }
  }
  const existing = working.objects?.field_kinds ?? [];
  const known = new Set(existing.map(declarationKey));
  const fresh = [
    ...new Map(declarations.map((item) => [declarationKey(item), item])).values(),
  ].filter((item) => !known.has(declarationKey(item)));
  const messages = data === undefined ? [] : checkDeclarations([...existing, ...fresh]);
  const next = migrateSynonyms(working, pairs, fresh);

  return (
    <Modal open title={OBJECT_TEXT.synonyms.title} onCancel={onClose} footer={null} width={680}>
      <div className="stack">
        <div className="small muted">{OBJECT_TEXT.synonyms.intro}</div>
        <div className="small muted">{OBJECT_TEXT.synonyms.builtin}</div>
        {objects.isError ? (
          <ErrorBar error={objects.error} onRetry={() => void objects.refetch()} />
        ) : null}
        {pairs.length === 0 ? <Empty title={OBJECT_TEXT.synonyms.empty} /> : null}
        {data === undefined && !objects.isError && pairs.length > 0 ? (
          <Loading height={120} />
        ) : null}

        {plan.map((item) => (
          <section
            key={`${item.pair[0]}|${item.pair[1]}`}
            className="stack-tight"
            aria-label={`${item.pair[0]} ↔ ${item.pair[1]}`}
          >
            <div className="field-label">
              <SafeText text={`${item.pair[0]} ↔ ${item.pair[1]}`} />
            </div>
            {pathWordWarnings(working, item.pair, OBJECT_TEXT.synonyms.groupWarn).map((warning) => (
              <div key={warning} className="field-warn">
                ▲ <SafeText text={warning} />
              </div>
            ))}
            {data === undefined ? null : item.affected.length === 0 ? (
              <div className="small muted">{OBJECT_TEXT.synonyms.none}</div>
            ) : (
              <>
                <div className="small muted">{OBJECT_TEXT.synonyms.affected}</div>
                <ul className="obj-rule-list">
                  {item.affected.map((row) => {
                    const choice = choiceOf(item.pair, row);
                    return (
                      <li key={row.id} className="obj-rule small">
                        <span className="obj-code">
                          <SafeText text={row.key} />
                        </span>
                        <select
                          aria-label={`${OBJECT_TEXT.synonyms.classTo} ${row.key}`}
                          className="native-input"
                          value={choice.kind}
                          onChange={(event) => change(item.pair, row, { kind: event.target.value })}
                        >
                          <option value={item.pair[0]}>{item.pair[0]}</option>
                          <option value={item.pair[1]}>{item.pair[1]}</option>
                        </select>
                        <select
                          aria-label={`${OBJECT_TEXT.synonyms.scopeTo} ${row.key}`}
                          className="native-input"
                          value={choice.scope}
                          onChange={(event) =>
                            change(item.pair, row, {
                              scope: event.target.value === "all" ? "all" : "only",
                            })
                          }
                        >
                          <option value="only">{OBJECT_TEXT.synonyms.scopeEvidence}</option>
                          <option value="all">{OBJECT_TEXT.synonyms.scopeAll}</option>
                        </select>
                      </li>
                    );
                  })}
                </ul>
              </>
            )}
          </section>
        ))}

        {messages.map((message) => (
          <div key={message} className="field-error" role="alert">
            {message}
          </div>
        ))}

        <div className="obj-foot">
          <button type="button" className="btn" onClick={onClose}>
            {OBJECT_TEXT.declare.cancel}
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={pairs.length === 0 || data === undefined || messages.length > 0}
            onClick={() => onApply(next)}
          >
            {OBJECT_TEXT.synonyms.apply}
          </button>
        </div>
      </div>
    </Modal>
  );
}
