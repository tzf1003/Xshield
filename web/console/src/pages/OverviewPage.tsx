import { WorkRoot } from "../work/WorkRoot";
import { Workbench } from "./workbench/Workbench";

/**
 * The workbench (`/`). It renders inside the work root so that the exact retry of a frozen write
 * offered under "待我处理" can complete an MFA step-up in place, like the page that owns it.
 */
export function OverviewPage() {
  return (
    <WorkRoot>
      <Workbench />
    </WorkRoot>
  );
}
