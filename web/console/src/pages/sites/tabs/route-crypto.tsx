import { Input, Radio } from "antd";
import { formatBytes } from "../../../sites/model/units.ts";
import type { Issue } from "../../../sites/model/validation.ts";
import { Field, NumInput } from "../fields";

const seconds = (value: unknown) => {
  const n = typeof value === "number" ? value : Number.NaN;
  return Number.isFinite(n) && n >= 0 && n < 8.64e12 / 1000
    ? `${new Date(n * 1000).toISOString().slice(0, 19).replace("T", " ")} UTC`
    : "—";
};
const num = (value: unknown): number => (typeof value === "number" ? value : Number.NaN);
const str = (value: unknown): string => (typeof value === "string" ? value : "");

type Crypto = Record<string, unknown> | null;

/** Request/response encryption: a mode, then only the fields that mode has. */
export function CryptoEditor({
  kind,
  value,
  maxResponseBytes,
  maxRequestBytes,
  issue,
  onChange,
}: {
  kind: "request" | "response";
  value: Crypto;
  maxResponseBytes: number;
  maxRequestBytes: number;
  issue: Issue | undefined;
  onChange: (next: Crypto) => void;
}) {
  const now = Math.floor(Date.now() / 1000);
  const mode = value === null ? "NONE" : str(value.mode) || "DIRECT_ENCRYPT";
  const patch = (change: Record<string, unknown>) => onChange({ ...(value ?? {}), ...change });
  const base = kind === "request" ? "req" : "res";
  function choose(next: string) {
    if (next === "NONE") onChange(null);
    else if (next === "OBSERVE") onChange({ mode: "OBSERVE", adapter_revision: "" });
    else if (next === "DIRECT_DECRYPT") {
      onChange({
        mode: "DIRECT_DECRYPT",
        adapter_revision: "",
        key_id: "",
        key_not_before: now,
        key_expires_at: now + 365 * 86_400,
        max_envelope_bytes: Math.min(65_536, maxRequestBytes),
        max_plaintext_bytes: Math.min(32_768, Math.floor(maxRequestBytes / 2)),
        max_message_age_seconds: 300,
        max_future_skew_seconds: 30,
        max_active_messages: 1000,
      });
    } else {
      onChange({
        mode: "DIRECT_ENCRYPT",
        adapter_revision: "",
        key_id: "",
        key_not_before: now,
        key_expires_at: now + 365 * 86_400,
        message_ttl_seconds: 300,
        max_envelope_bytes: maxResponseBytes * 2 + 1024,
      });
    }
  }
  const options =
    kind === "request"
      ? ([
          ["NONE", "无"],
          ["OBSERVE", "仅观察信封"],
          ["DIRECT_DECRYPT", "直接解密"],
        ] as const)
      : ([
          ["NONE", "无"],
          ["DIRECT_ENCRYPT", "直接加密"],
        ] as const);
  return (
    <>
      <Field
        id={`${base}-crypto-mode`}
        group
        label={kind === "request" ? "请求加密" : "响应加密"}
        issue={issue}
      >
        <Radio.Group
          aria-label={kind === "request" ? "请求加密" : "响应加密"}
          value={mode}
          onChange={(event) => choose(event.target.value)}
        >
          {options.map(([option, label]) => (
            <Radio.Button key={option} value={option}>
              {label}
            </Radio.Button>
          ))}
        </Radio.Group>
      </Field>
      {value !== null && (
        <div className="xs-crypto-fields">
          <Field
            id={`${base}-crypto-adapter`}
            label="适配器版本"
            hint="字母、数字和 _ . -，例如 envelope-v1。"
          >
            <Input
              value={str(value.adapter_revision)}
              spellCheck={false}
              onChange={(event) => patch({ adapter_revision: event.target.value })}
            />
          </Field>
          {mode !== "OBSERVE" && (
            <>
              <Field
                id={`${base}-crypto-key`}
                label="Key ID"
                hint="部署侧管理的密钥标识；每站点最多一把请求解密密钥和一把响应加密密钥，且不得共用。"
              >
                <Input
                  value={str(value.key_id)}
                  spellCheck={false}
                  onChange={(event) => patch({ key_id: event.target.value })}
                />
              </Field>
              <Field
                id={`${base}-crypto-from`}
                label="密钥生效时间"
                hint={`Unix 秒。= ${seconds(value.key_not_before)}`}
              >
                <NumInput
                  value={num(value.key_not_before)}
                  min={0}
                  unit="秒"
                  onChange={(next) => patch({ key_not_before: next })}
                />
              </Field>
              <Field
                id={`${base}-crypto-until`}
                label="密钥失效时间"
                hint={`Unix 秒，须晚于生效时间。= ${seconds(value.key_expires_at)}`}
              >
                <NumInput
                  value={num(value.key_expires_at)}
                  min={0}
                  unit="秒"
                  onChange={(next) => patch({ key_expires_at: next })}
                />
              </Field>
              <Field
                id={`${base}-crypto-envelope`}
                label="信封上限"
                hint={
                  kind === "request"
                    ? `最大 64 KiB 且不超过请求体上限。当前 = ${formatBytes(num(value.max_envelope_bytes))}。`
                    : `不小于两倍响应上限加 1024 字节（${formatBytes(maxResponseBytes * 2 + 1024)}）。当前 = ${formatBytes(num(value.max_envelope_bytes))}。`
                }
              >
                <NumInput
                  value={num(value.max_envelope_bytes)}
                  min={1}
                  unit="字节"
                  onChange={(next) => patch({ max_envelope_bytes: next })}
                />
              </Field>
            </>
          )}
          {mode === "DIRECT_DECRYPT" && (
            <>
              <Field
                id="req-crypto-plain"
                label="明文上限"
                hint="不超过信封的一半，也不超过请求体上限。"
              >
                <NumInput
                  value={num(value.max_plaintext_bytes)}
                  min={1}
                  unit="字节"
                  onChange={(next) => patch({ max_plaintext_bytes: next })}
                />
              </Field>
              <Field id="req-crypto-age" label="消息有效期" hint="1–3600 秒。">
                <NumInput
                  value={num(value.max_message_age_seconds)}
                  min={1}
                  max={3600}
                  unit="秒"
                  onChange={(next) => patch({ max_message_age_seconds: next })}
                />
              </Field>
              <Field
                id="req-crypto-skew"
                label="允许的未来偏差"
                hint="0–300 秒，容忍客户端时钟快于服务端的时间。"
              >
                <NumInput
                  value={num(value.max_future_skew_seconds)}
                  min={0}
                  max={300}
                  unit="秒"
                  onChange={(next) => patch({ max_future_skew_seconds: next })}
                />
              </Field>
              <Field
                id="req-crypto-active"
                label="同时有效的消息数"
                hint="1–1,000,000，用于重放保护的容量。"
              >
                <NumInput
                  value={num(value.max_active_messages)}
                  min={1}
                  max={1_000_000}
                  onChange={(next) => patch({ max_active_messages: next })}
                />
              </Field>
            </>
          )}
          {mode === "DIRECT_ENCRYPT" && (
            <Field id="res-crypto-ttl" label="消息有效期" hint="1–3600 秒。">
              <NumInput
                value={num(value.message_ttl_seconds)}
                min={1}
                max={3600}
                unit="秒"
                onChange={(next) => patch({ message_ttl_seconds: next })}
              />
            </Field>
          )}
        </div>
      )}
    </>
  );
}
