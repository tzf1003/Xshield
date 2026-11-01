// Candidate rules offered from a single request (docs/06 6.4.10 flows A and B). The API preview
// counts how many requests each candidate would reach; this module only proposes the shapes.

const STATIC_EXT = /\.(js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|webp|avif)$/i;
const STATIC_DIR = /^\/(static|assets|public|fonts|images)\//;

export function isStaticAsset(path: string): boolean {
  return STATIC_EXT.test(path) || STATIC_DIR.test(path);
}

export type Candidate = { label: string; rule: string; note?: string };

function parentOf(path: string): string | null {
  const index = path.lastIndexOf("/");
  if (index <= 0) return null;
  return path.slice(0, index);
}

/** Entry candidates: the exact path (default), then the parent path as a prefix. */
export function entryCandidates(path: string): Candidate[] {
  const candidates: Candidate[] = [{ label: "精确路径", rule: path }];
  const parent = parentOf(path);
  if (parent !== null && parent.split("/").filter(Boolean).length >= 2) {
    candidates.push({
      label: "父路径前缀",
      rule: `${parent}/*`,
      note: "前缀入口会放大无会话可达的范围",
    });
  }
  return candidates;
}

/** Bypass candidates: exact path, the containing directory, and the top-level directory. */
export function bypassCandidates(path: string): Candidate[] {
  const candidates: Candidate[] = [{ label: "精确路径", rule: path }];
  const parent = parentOf(path);
  if (parent !== null) candidates.push({ label: "所在目录", rule: `${parent}/*` });
  const top = /^\/[^/]+\//.exec(path)?.[0];
  if (top && top !== `${parent}/`) candidates.push({ label: "顶层目录", rule: `${top}*` });
  return candidates;
}
