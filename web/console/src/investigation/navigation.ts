import { useRouter } from "@tanstack/react-router";
import { useCallback } from "react";
import {
  PREFILL_PARAM,
  type SearchPreset,
  encodePrefill,
  searchLocation,
} from "./search-preset.ts";

/** Fixed detail and list addresses of the investigation pages. */
export const requestListPath = "/investigation/requests";
export const requestPath = (id: string) => `/investigation/requests/${id}`;
export const modelListPath = "/investigation/models";
export const modelPath = (id: string) => `/investigation/models/${id}`;
export const agentListPath = "/investigation/agents";
export const agentPath = (id: string) => `/investigation/agents/${id}`;
export const grantListPath = "/investigation/grants";
export const grantPath = (id: string) => `/investigation/grants/${id}`;
export const bindingListPath = "/investigation/bindings";
export const bindingPath = (id: string) => `/investigation/bindings/${id}`;
export const calibrationListPath = "/investigation/calibration";
export const calibrationPath = (id: string) => `/investigation/calibration/${id}`;
export const searchPath = "/investigation/search";

/** A real address for a search prefilled with one condition (middle-click and copy-link work). */
export function searchHref(preset: SearchPreset): string {
  return `${searchPath}?${new URLSearchParams({ [PREFILL_PARAM]: encodePrefill(preset) })}`;
}

/** Router navigation for page code. Navigating never submits anything by itself. */
export function useInvestigationNavigate() {
  const router = useRouter();
  const go = useCallback(
    (to: string, search?: Record<string, string>) => {
      void router.navigate({ to, search } as never);
    },
    [router],
  );
  const openSearch = useCallback(
    (preset: SearchPreset) => {
      void router.navigate(searchLocation(preset) as never);
    },
    [router],
  );
  return { go, openSearch };
}
