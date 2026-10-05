import { useRouter } from "@tanstack/react-router";
import type { MouseEvent } from "react";
import type { SiteSection } from "../../../admin-routes.ts";
import type { ChangeGroup } from "../../../sites/model/diff.ts";
import { sectionLabel } from "../../../sites/sections.ts";

type Props = {
  basePath: string;
  sections: readonly SiteSection[];
  current: SiteSection;
  /** Unsaved edits per editor section, shown as a count beside its name. */
  unsaved: ReadonlyMap<ChangeGroup, number>;
};

/**
 * The site's sections as real links (middle-click, copy address and the back button all work),
 * styled as tabs. Only the current section is rendered below; a count marks the sections that
 * hold unsaved edits. The count is described, not part of the link name, so the name stays
 * the section's name.
 */
export function SectionNav({ basePath, sections, current, unsaved }: Props) {
  const router = useRouter();
  function go(event: MouseEvent, path: string) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
      return;
    }
    event.preventDefault();
    void router.navigate({ to: path } as never);
  }
  return (
    <nav className="xs-section-nav" aria-label="站点运营导航">
      <ul>
        {sections.map((key) => {
          const count = unsaved.get(key as ChangeGroup) ?? 0;
          const describedBy = count > 0 ? `xs-unsaved-${key}` : undefined;
          return (
            <li key={key}>
              <a
                href={`${basePath}/${key}`}
                aria-current={current === key ? "page" : undefined}
                aria-describedby={describedBy}
                onClick={(event) => go(event, `${basePath}/${key}`)}
              >
                {sectionLabel[key]}
                {count > 0 && (
                  <span className="xs-tab-count" aria-hidden="true">
                    {count}
                  </span>
                )}
              </a>
              {count > 0 && (
                <span id={describedBy} className="xs-visually-hidden">
                  {count} 项未保存修改
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
