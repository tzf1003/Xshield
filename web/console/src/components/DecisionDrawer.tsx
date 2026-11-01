import { Descriptions, Drawer, Table } from "antd";
import type { DecisionLogRow } from "../types.ts";

interface DecisionDrawerProps {
  row: DecisionLogRow | null;
  onClose: () => void;
}

function probabilityRows(map: Record<string, number>): { option: string; probability: number }[] {
  return Object.entries(map).map(([option, probability]) => ({ option, probability }));
}

export function DecisionDrawer({ row, onClose }: DecisionDrawerProps) {
  return (
    <Drawer
      title={row ? `判定记录 #${row.id}` : ""}
      open={row !== null}
      onClose={onClose}
      width={480}
    >
      {row && (
        <>
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="时间">
              {new Date(row.at_millis).toLocaleString()}
            </Descriptions.Item>
            <Descriptions.Item label="站点">{row.site}</Descriptions.Item>
            <Descriptions.Item label="请求 ID">{row.request_id}</Descriptions.Item>
            <Descriptions.Item label="会话前缀">{row.session}</Descriptions.Item>
            <Descriptions.Item label="方法">{row.method}</Descriptions.Item>
            <Descriptions.Item label="路径">{row.path}</Descriptions.Item>
            <Descriptions.Item label="状态码">{row.status ?? "—"}</Descriptions.Item>
            <Descriptions.Item label="判定路径">{row.decision_path}</Descriptions.Item>
            <Descriptions.Item label="结论">{row.outcome}</Descriptions.Item>
          </Descriptions>

          {row.jev ? (
            <>
              <h3 style={{ marginTop: 24 }}>Jev 看到的内容</h3>
              <Descriptions column={1} size="small" bordered>
                <Descriptions.Item label="脱敏后的 state">
                  <pre style={{ whiteSpace: "pre-wrap", margin: 0 }}>{row.jev.state}</pre>
                </Descriptions.Item>
                <Descriptions.Item label="耗时">{row.jev.millis} ms</Descriptions.Item>
              </Descriptions>

              <h4 style={{ marginTop: 16 }}>是否有权限访问（access）</h4>
              <Table
                size="small"
                pagination={false}
                rowKey="option"
                dataSource={probabilityRows(row.jev.access)}
                columns={[
                  { title: "选项", dataIndex: "option" },
                  { title: "概率", dataIndex: "probability" },
                ]}
              />

              <h4 style={{ marginTop: 16 }}>是否为攻击（attack）</h4>
              <Table
                size="small"
                pagination={false}
                rowKey="option"
                dataSource={probabilityRows(row.jev.attack)}
                columns={[
                  { title: "选项", dataIndex: "option" },
                  { title: "概率", dataIndex: "probability" },
                ]}
              />
            </>
          ) : (
            <p style={{ marginTop: 24, color: "rgba(0,0,0,0.45)" }}>
              此记录未调用 Jev（例如快速放行或无会话拒绝）。
            </p>
          )}
        </>
      )}
    </Drawer>
  );
}
