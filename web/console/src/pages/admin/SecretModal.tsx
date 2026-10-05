import { CheckOutlined, CopyOutlined, KeyOutlined } from "@ant-design/icons";
import { Alert, Button, Checkbox, Modal, Space } from "antd";
import { useEffect, useId, useState, useSyncExternalStore } from "react";
import { scopeSummary } from "../../operations/api-keys.ts";
import { keySecrets } from "../../operations/key-secret.ts";
import { useSession } from "../../security/SessionProvider";
import { TimeStamp } from "../../ui/TimeStamp";
import { Facts } from "../../work/Parts";

/**
 * The one and only time a key's plaintext is shown. It cannot be dismissed by Escape, the mask
 * or a close icon: the operator confirms "我已保存" and then closes it, which drops the plaintext
 * from memory (the store entry, this component's state and, with `destroyOnHidden`, the DOM).
 * The plaintext is never put in an attribute (title, aria-label, value of a field), a URL, the
 * document title or a log; the copy button's name says what it copies, not the value.
 */
export function SecretModal() {
  const { runtime, state } = useSession();
  const store = keySecrets(runtime);
  const snapshot = useSyncExternalStore(store.subscribe, store.getSnapshot);
  // Only a secret received in this session lifetime is ever shown.
  const issued = snapshot.pending.find((item) => item.epoch === state.epoch) ?? null;
  const [stored, setStored] = useState(false);
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const confirmId = useId();
  const current = issued?.apiKeyId ?? null;
  useEffect(() => {
    // A new secret starts unconfirmed and uncopied.
    void current;
    setStored(false);
    setCopied("idle");
  }, [current]);

  if (!issued) return null;

  async function copy(secret: string) {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied("copied");
    } catch {
      setCopied("failed");
    }
  }

  return (
    <Modal
      open
      title={
        issued.kind === "rotated"
          ? "新 API Key 明文（只显示这一次）"
          : "API Key 明文（只显示这一次）"
      }
      closable={false}
      keyboard={false}
      mask={{ closable: false }}
      destroyOnHidden
      width={640}
      footer={
        <Space wrap className="xs-key-secret-footer">
          <Checkbox
            id={confirmId}
            checked={stored}
            onChange={(event) => setStored(event.target.checked)}
          >
            我已把明文保存到安全位置
          </Checkbox>
          <Button
            type="primary"
            disabled={!stored}
            onClick={() => store.acknowledge(issued.apiKeyId)}
          >
            关闭并清除明文
          </Button>
        </Space>
      }
    >
      <div className="xs-w-stack">
        <Alert
          type="warning"
          showIcon
          title="关闭后无法再次查看"
          description="服务端只保存这把 Key 的指纹，控制台也不会保存明文。请现在复制并保存到密钥管理系统；遗失后只能轮换出新 Key。"
        />
        <div className="xs-key-secret">
          <KeyOutlined aria-hidden="true" />
          <code className="mono xs-key-secret-value">{issued.secret}</code>
          <Button
            icon={
              copied === "copied" ? (
                <CheckOutlined aria-hidden="true" />
              ) : (
                <CopyOutlined aria-hidden="true" />
              )
            }
            onClick={() => void copy(issued.secret)}
          >
            {copied === "copied" ? "已复制" : "复制明文"}
          </Button>
        </div>
        {copied === "failed" && (
          <Alert type="error" showIcon title="浏览器拒绝了剪贴板访问，请手动选中上面的明文复制。" />
        )}
        {issued.replaced && (
          <Alert
            type="info"
            showIcon
            title="旧 Key 已在同一事务中撤销"
            description={<span className="mono">{issued.replaced}</span>}
          />
        )}
        <Facts
          rows={[
            ["名称", issued.displayName],
            [
              "Agent 主体",
              <span key="s" className="mono">
                {issued.subject}
              </span>,
            ],
            [
              "Key ID",
              <span key="k" className="mono">
                {issued.apiKeyId}
              </span>,
            ],
            [
              "前缀",
              <span key="p" className="mono">
                {issued.keyPrefix}
              </span>,
            ],
            ["到期", <TimeStamp key="e" value={issued.expiresAt} />],
            [
              "范围",
              <ul key="r" className="xs-key-problems">
                {scopeSummary(issued.scopes).map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>,
            ],
          ]}
        />
        <p className="xs-w-muted">
          使用方式：请求头 <code>X-Xshield-API-Key</code> 携带明文，
          <code>X-Xshield-Agent-Run-Id</code> 携带本次运行 ID。
        </p>
      </div>
    </Modal>
  );
}
