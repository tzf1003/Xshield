// The "模型" tab (design agent-model-ui 2.1): the Jev configuration above the learning agent's. The page reads
// GET /api/system/models once; the Jev card asks again every five seconds while a saved version is still on its
// way to the gateways, and every thirty seconds while a gateway is still behind (design 2.5).

import { useSystemModels } from "../../api/queries.ts";
import { useNowBucket } from "../../app/scope.ts";
import {
  jevBehind,
  jevWaitingForLoad,
  LOAD_POLL_MS,
  LOAD_RECHECK_MS,
} from "../../lib/model-status.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { AgentModelCard, JevModelCard } from "./ModelCard.tsx";

export function ModelsPanel() {
  const now = useNowBucket(5_000);
  const models = useSystemModels((data) => {
    if (jevWaitingForLoad(data?.jev, Date.now())) return LOAD_POLL_MS;
    return jevBehind(data?.jev) ? LOAD_RECHECK_MS : false;
  });

  if (models.isPending) return <Loading height={160} />;
  if (!models.data) {
    return <ErrorBar error={models.error} onRetry={() => void models.refetch()} />;
  }
  const { jev, agent } = models.data;
  return (
    <div className="sys-models">
      <JevModelCard jev={jev} now={now} />
      <AgentModelCard agent={agent} jevRoute={jev.route} jevConsole={jev.source === "console"} />
    </div>
  );
}
