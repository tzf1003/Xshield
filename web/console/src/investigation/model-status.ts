import type { PillTone } from "../ui/TonePill";

/** Lifecycle states of a model call, as the server records them, with a tone and a word. */
export const modelStatusTone: Readonly<Record<string, PillTone>> = {
  success: "allow",
  error: "deny",
  timeout: "deny",
  cancelled: "deny",
  started: "observe",
  requested: "observe",
};

export const modelStatusWords: Readonly<Record<string, string>> = {
  success: "成功",
  error: "出错",
  timeout: "超时",
  cancelled: "已取消",
  started: "已开始",
  requested: "已请求",
};

export const modelTone = (status: string): PillTone => modelStatusTone[status] ?? "unknown";
export const modelWord = (status: string): string => modelStatusWords[status] ?? "未识别";
