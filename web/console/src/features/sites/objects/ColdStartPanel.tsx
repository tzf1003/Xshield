// The cold start of an empty object map (console design 3.6): the classes that the recent requests name clearly, offered
// as the starting point of learning. A candidate that needs a look is left unchecked. Confirming writes the chosen ones
// into the draft through the save dialog; skipping hides the list here, and learning goes on without it.

import { useState } from "react";
import { useBootstrap } from "../../../api/queries.ts";
import type { BootstrapCandidate, FieldKindDeclaration, SiteSpec } from "../../../api/types.ts";
import { checkDeclarations, declarationKey } from "../../../lib/objects-validate.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { Card, ErrorBar, Loading } from "../../../ui/Page.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { candidateDeclarations, withDeclarations } from "./objects-model.ts";

type Props = {
  site: string;
  working: SiteSpec;
  onApply: (spec: SiteSpec) => void;
  onLater: () => void;
};

export function ColdStartPanel({ site, working, onApply, onLater }: Props) {
  const boot = useBootstrap(site);
  const [picked, setPicked] = useState<Record<string, boolean>>({});

  const candidates = boot.data?.candidates ?? [];
  const usable = (item: BootstrapCandidate) => candidateDeclarations(item).length > 0;
  // A candidate is checked by default when it is clear (no note) and names at least one position with a field.
  const isChecked = (item: BootstrapCandidate) =>
    picked[item.kind] ?? (item.note === null && usable(item));
  const chosen = candidates.filter((item) => isChecked(item) && usable(item));

  const existing = working.advanced?.field_kinds ?? [];
  const known = new Set(existing.map(declarationKey));
  const declared: FieldKindDeclaration[] = chosen.flatMap(candidateDeclarations);
  const fresh = [...new Map(declared.map((item) => [declarationKey(item), item])).values()].filter(
    (item) => !known.has(declarationKey(item)),
  );
  const messages = checkDeclarations([...existing, ...fresh]);

  return (
    <Card title={OBJECT_TEXT.coldStart.title}>
      {boot.isPending ? <Loading height={160} /> : null}
      {boot.isError ? <ErrorBar error={boot.error} onRetry={() => void boot.refetch()} /> : null}
      {boot.data === undefined ? null : (
        <div className="stack">
          <div className="small">
            {OBJECT_TEXT.coldStart.intro(boot.data.window_hours, candidates.length)}
          </div>
          {candidates.length === 0 ? (
            <div className="small muted">{OBJECT_TEXT.coldStart.none}</div>
          ) : (
            <ul className="obj-rule-list">
              {candidates.map((item) => (
                <li key={item.kind}>
                  <label className="obj-rule">
                    <input
                      type="checkbox"
                      checked={isChecked(item)}
                      disabled={!usable(item)}
                      onChange={(event) =>
                        setPicked((previous) => ({
                          ...previous,
                          [item.kind]: event.target.checked,
                        }))
                      }
                    />
                    <span>
                      <span className="obj-class-name">
                        <SafeText text={item.name} />
                      </span>{" "}
                      <span className="mono small dim">
                        <SafeText text={item.kind} />
                      </span>
                    </span>
                    <span className="obj-code">
                      <SafeText text={item.slots.join(" · ")} />
                    </span>
                    {item.note === null ? null : (
                      <span className="field-warn">
                        ▲ <SafeText text={item.note} />
                      </span>
                    )}
                    {usable(item) ? null : (
                      <span className="small muted">{OBJECT_TEXT.coldStart.pathOnly}</span>
                    )}
                  </label>
                </li>
              ))}
            </ul>
          )}

          {messages.map((message) => (
            <div key={message} className="field-error" role="alert">
              {message}
            </div>
          ))}

          <div className="obj-foot">
            <button type="button" className="btn" onClick={onLater}>
              {OBJECT_TEXT.coldStart.later}
            </button>
            <button
              type="button"
              className="btn-primary"
              disabled={chosen.length === 0 || messages.length > 0}
              onClick={() => onApply(withDeclarations(working, fresh))}
            >
              {OBJECT_TEXT.coldStart.confirm(chosen.length)}
            </button>
          </div>
        </div>
      )}
    </Card>
  );
}
