/** Human readings of the numbers operators type, shown beside the raw value. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "—";
  const mib = 1024 * 1024;
  if (bytes >= mib && bytes % mib === 0) return `${bytes / mib} MiB`;
  if (bytes >= 1024 && bytes % 1024 === 0) return `${bytes / 1024} KiB`;
  return `${bytes.toLocaleString("en-US")} 字节`;
}

export function formatSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds >= 86_400 && seconds % 86_400 === 0) return `${seconds / 86_400} 天`;
  if (seconds >= 3600 && seconds % 3600 === 0) return `${seconds / 3600} 小时`;
  if (seconds >= 60 && seconds % 60 === 0) return `${seconds / 60} 分钟`;
  return `${seconds} 秒`;
}

export function formatMillis(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  return ms >= 1000 && ms % 1000 === 0 ? `${ms / 1000} 秒` : `${ms} 毫秒`;
}
