// The "模型" tab (design agent-model-ui 2.1): the Jev configuration above the learning agent's. The page reads
// GET /api/system/models once; the Jev card asks again every five seconds only while a saved version is still on its
// way to the gateways (design 2.5).

import { useSystemModels } from "../../api/queries.ts";
import { useNowBucket } from "../../app/scope.ts";
import { jevWaitingForLoad, LOAD_POLL_MS } from "../../lib/model-status.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { AgentModelCard, JevModelCard } from "./ModelCard.tsx";

export function ModelsPanel() {
  const now = useNowBucket(5_000);
  const models = useSystemModels((data) =>
    jevWaitingForLoad(data?.jev, Date.now()) ? LOAD_POLL_MS : false,
  );

  if (models.isPending) return <Loading height={160} />;
  if (!models.data) {
    return <ErrorBar error={models.error} onRetry={() => void models.refetch()} />;
  }
  const { jev, agent } = models.data;
  return (
    <div className="sys-models">
      <JevModelCard jev={jev} now={now} />
      <AgentModelCard agent={agent} jevRoute={jev.route} />
    </div>
  );
}
