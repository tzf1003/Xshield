import { useParams } from "@tanstack/react-router";
import { canonicalWizardStep } from "../../admin-routes.ts";
import { NewSiteWizard } from "./NewSiteWizard";

/**
 * `/sites/new/{step}`. The step is only the address: the wizard stays mounted while it changes,
 * which is what keeps the draft across steps and across the browser's back and forward.
 */
export function NewSiteRoute() {
  const params = useParams({ strict: false }) as { step?: string };
  return <NewSiteWizard step={canonicalWizardStep(params.step ?? "") ?? "basics"} />;
}
