/** Access-approval lifetimes: three presets, never above the server's configured maximum. */

export const TTL_PRESETS: readonly { seconds: number; label: string }[] = [
  { seconds: 900, label: "15 分钟" },
  { seconds: 3600, label: "1 小时" },
  { seconds: 14_400, label: "4 小时" },
];

/** The presets the server maximum still allows. */
export function ttlPresets(maxSeconds: number): readonly { seconds: number; label: string }[] {
  return TTL_PRESETS.filter((preset) => preset.seconds <= maxSeconds);
}

export function ttlProblem(seconds: number | null, maxSeconds: number): string | null {
  if (seconds === null || !Number.isSafeInteger(seconds)) return "请选择批准期限";
  if (seconds < 1) return "批准期限至少 1 秒";
  if (seconds > maxSeconds) return `批准期限最多 ${maxSeconds} 秒（服务端上限）`;
  return null;
}

export function formatTtl(seconds: number): string {
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60)
    return seconds % 60 === 0 ? `${minutes} 分钟` : `${minutes} 分 ${seconds % 60} 秒`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest === 0 ? `${hours} 小时` : `${hours} 小时 ${rest} 分钟`;
}
