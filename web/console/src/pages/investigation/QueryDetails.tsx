import { Collapse, Descriptions } from "antd";
import { displayPlan } from "../../investigation/plans.ts";
import type { SearchPlan, SearchResponse } from "../../search.ts";
import { ObjectId } from "../../ui/ObjectId";
import { EventTime } from "../../ui/EventTime";

export function scanText(value: number | null): string {
  return value === null ? "未知（索引未报告）" : value.toLocaleString();
}

/**
 * The submitted plan and what the server reported for each loaded page. Unknown scan statistics
 * are shown as unknown, never as zero, and a subject reference is not repeated on screen.
 */
export function QueryDetails({
  plan,
  pages,
  label = "查询详情",
}: {
  plan: SearchPlan;
  pages: readonly SearchResponse[];
  label?: string;
}) {
  return (
    <Collapse
      size="small"
      className="xs-details"
      items={[
        {
          key: "details",
          label,
          children: (
            <section aria-label="已提交查询计划" className="xs-plan-region">
              <p className="xs-plan-note">
                下面是已提交并通过校验的查询计划；分页沿用该计划，编辑条件会使旧结果与游标失效。时间为
                UTC 整秒半开窗口。
              </p>
              <pre className="mono xs-plan">{JSON.stringify(displayPlan(plan), null, 2)}</pre>
              {pages.map((page, index) => (
                <Descriptions
                  key={page.request_id}
                  size="small"
                  bordered
                  column={{ xs: 1, sm: 1, md: 2 }}
                  title={pages.length > 1 ? `第 ${index + 1} 页` : undefined}
                  items={[
                    {
                      key: "digest",
                      label: "查询摘要",
                      children: <span className="mono">{page.query_digest}</span>,
                    },
                    {
                      key: "request",
                      label: "管理请求 ID",
                      children: <ObjectId value={page.request_id} quietCopy />,
                    },
                    { key: "rows", label: "实际扫描行", children: scanText(page.scanned_rows) },
                    { key: "bytes", label: "实际扫描字节", children: scanText(page.scanned_bytes) },
                    {
                      key: "as_of",
                      label: "索引观察时间",
                      children: <EventTime value={page.as_of} precision="millisecond" />,
                    },
                    {
                      key: "returned",
                      label: "本页返回",
                      children: `${page.events.length} 条${page.truncated ? "（还有后续页）" : "（已读完）"}`,
                    },
                  ]}
                />
              ))}
            </section>
          ),
        },
      ]}
    />
  );
}
