// The way from the object map to the learning agent's model settings. The system page's models tab comes with the
// model settings; until it is on main, the link opens the system page, and this one place moves it to the tab.

import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

export function ModelsLink({ children }: { children: ReactNode }) {
  return <Link to="/system">{children}</Link>;
}
