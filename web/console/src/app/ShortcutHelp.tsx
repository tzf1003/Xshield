// The shortcut sheet opened with `?` (docs/06 6.3.4). The keys listed here are the only ones bound.

import { Modal } from "antd";

const KEYS: Array<[string, string]> = [
  ["⌘K / Ctrl K", "打开命令面板"],
  ["/", "聚焦本页的筛选框"],
  ["g 然后 o r s j c y", "跳到 总览、请求追溯、会话、Jev 调用、站点、系统"],
  ["j / k", "下一行 / 上一行，预览面板跟随（列表、会话时间线）"],
  ["Enter", "打开选中行的详情"],
  ["Esc", "关闭面板和对话框；详情页返回列表"],
  ["[ / ]", "同一会话的上一个 / 下一个请求（请求详情）"],
  ["1 – 5", "切换详情页的标签"],
  ["v", "循环切换 Jev 上下文的视图"],
  ["c", "复制当前请求或选中行的请求 ID"],
  ["l", "打开或关闭实时模式（请求追溯）"],
  ["⌘S / Ctrl S", "打开保存对话框（站点配置）"],
  ["?", "显示这份快捷键说明"],
];

type Props = {
  open: boolean;
  onClose: () => void;
};

export function ShortcutHelp({ open, onClose }: Props) {
  return (
    <Modal open={open} onCancel={onClose} footer={null} title="快捷键" width={560}>
      <div className="help-grid">
        {KEYS.map(([keys, text]) => (
          <div key={keys} style={{ display: "contents" }}>
            <kbd>{keys}</kbd>
            <span>{text}</span>
          </div>
        ))}
      </div>
      <p className="toolbar-note" style={{ marginTop: 14 }}>
        焦点在输入框或编辑器里时，只有 ⌘K、Esc 和 ⌘S 生效。
      </p>
    </Modal>
  );
}
