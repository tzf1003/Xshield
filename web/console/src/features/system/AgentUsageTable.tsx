// The sites that have the learning agent on, with what each used of its daily limit today (design 2.1). A site name
// opens that site's objects tab, where its learning and its agent verdicts are.

import { Link } from "@tanstack/react-router";
import type { AgentSiteUsage } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { MODEL_TEXT } from "../../lib/vocab.ts";
import { shortDateTime } from "./clock.ts";

export function AgentUsageTable({ sites }: { sites: AgentSiteUsage[] }) {
  const enabled = sites.filter((site) => site.enabled).sort((a, b) => a.site.localeCompare(b.site));
  if (enabled.length === 0) return <p className="muted small">{MODEL_TEXT.sitesEmpty}</p>;
  return (
    <div className="tbl-wrap">
      <table className="tbl sys-mini">
        <caption className="sr-only">{MODEL_TEXT.siteUsage}</caption>
        <thead>
          <tr>
            <th scope="col">{MODEL_TEXT.colSite}</th>
            <th scope="col" className="num">
              {MODEL_TEXT.colUsed}
            </th>
            <th scope="col" className="num">
              {MODEL_TEXT.colFailed}
            </th>
            <th scope="col">{MODEL_TEXT.colLast}</th>
          </tr>
        </thead>
        <tbody>
          {enabled.map((site) => {
            const last = site.last_call_at === null ? Number.NaN : Date.parse(site.last_call_at);
            return (
              <tr key={site.site}>
                <td className="mono">
                  <Link to="/sites/$name" params={{ name: site.site }} search={{ tab: "objects" }}>
                    {site.site}
                  </Link>
                </td>
                <td className="num tnum">{`${fmtInt(site.used)} / ${fmtInt(site.limit)}`}</td>
                <td className="num tnum">{fmtInt(site.failed)}</td>
                <td className="tnum">{Number.isNaN(last) ? "—" : shortDateTime(last)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
