// The message for a configuration the server refused (docs/06 6.6.5). A host clash names the host, so the user
// sees which one to change; every other code reads from the shared table.

import { ApiError } from "../../api/client.ts";
import type { SiteSpec } from "../../api/types.ts";
import { errorText } from "../../lib/vocab.ts";

export function serverProblem(code: string, field: string | undefined, spec: SiteSpec): string {
  if (code === "SITE_HOST_TAKEN" && field) {
    const index = /^hosts\[(\d+)\]$/.exec(field)?.[1];
    const host = index === undefined ? field : spec.hosts[Number(index)];
    return `Host ${host ?? field} 已属于其他站点`;
  }
  return errorText(code);
}

/** The text of any failed request about a configuration; errors that are not from the API stay generic. */
export function requestProblem(error: unknown, spec: SiteSpec): string {
  if (error instanceof ApiError) return serverProblem(error.code ?? "", error.field, spec);
  return errorText(undefined);
}
