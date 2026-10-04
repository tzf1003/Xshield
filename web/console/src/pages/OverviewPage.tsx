import { ReloadOutlined } from "@ant-design/icons";
import { useRouter } from "@tanstack/react-router";
import { Button } from "antd";
import { OverviewWorkbench } from "../OverviewWorkbench";
import { useGuardedQuery } from "../security/hooks";
import { MANUAL_REFRESH } from "../security/query-client.ts";
import { PageActions } from "../shell/page-actions";

function observedAt(value: string | undefined) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("zh-CN", { hour12: false });
}

/**
 * First page on the new data layer: the snapshot is an epoch-keyed, scope-verified guarded query
 * that is read once on arrival and afterwards only when the operator presses refresh.
 */
export function OverviewPage() {
  const router = useRouter();
  const query = useGuardedQuery({
    key: ["workbench", "overview"],
    fetch: (client, signal) => client.workbenchOverview(signal),
    staleTime: MANUAL_REFRESH,
  });
  const observed = observedAt(query.data?.as_of);
  return (
    <>
      <PageActions>
        {observed && <span className="xs-observed">观察于 {observed}</span>}
        <Button
          icon={<ReloadOutlined />}
          loading={query.isFetching}
          onClick={() => void query.refetch()}
        >
          刷新快照
        </Button>
      </PageActions>
      <div className="legacy">
        <OverviewWorkbench
          overview={query.data ?? null}
          failed={query.isError}
          onNavigate={(path) => void router.navigate({ to: path } as never)}
        />
      </div>
    </>
  );
}
