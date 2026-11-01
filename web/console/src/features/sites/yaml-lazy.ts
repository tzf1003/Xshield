// The YAML editor is loaded on first use, so CodeMirror stays out of the main bundle (docs/07 7.10.7).

import { lazy } from "react";

export const LazyYamlEditor = lazy(() =>
  import("./YamlEditor.tsx").then((module) => ({ default: module.YamlEditor })),
);
