// The object map tab is loaded when it first opens, as the YAML editor is (yaml-lazy.ts): most visits to a site never
// open it, and the request pages load the site page's modules too.

import { lazy } from "react";

export const LazyObjectsTab = lazy(() =>
  import("./ObjectsTab.tsx").then((module) => ({ default: module.ObjectsTab })),
);
