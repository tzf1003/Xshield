// The question the agent would get for one waiting position, read-only (console design 3.1): the position, its response
// structure, its flows and the candidate kinds, with no values. Seeing it is what makes it safe to turn the agent on.

import { Modal } from "antd";
import type { ReactNode } from "react";
import { ApiError } from "../../../api/client.ts";
import { useAgentSample } from "../../../api/queries.ts";
import { OBJECT_AGENT_TEXT } from "../../../lib/vocab.ts";
import { ErrorBar, Loading, Notice } from "../../../ui/Page.tsx";
import { AgentInputView } from "./AgentInputView.tsx";

type Props = { site: string; onClose: () => void };

export function AgentSampleDialog({ site, onClose }: Props) {
  const sample = useAgentSample(site, true);

  let body: ReactNode;
  if (sample.isPending) body = <Loading height={120} />;
  else if (sample.error instanceof ApiError && sample.error.status === 404)
    body = <Notice>{OBJECT_AGENT_TEXT.sample.none}</Notice>;
  else if (sample.isError)
    body = <ErrorBar error={sample.error} onRetry={() => void sample.refetch()} />;
  else body = <AgentInputView input={sample.data} />;

  return (
    <Modal open title={OBJECT_AGENT_TEXT.sample.title} onCancel={onClose} footer={null} width={640}>
      <div className="small muted">{OBJECT_AGENT_TEXT.sample.note}</div>
      {body}
    </Modal>
  );
}
