// The one QueryClient of the console. Client errors (4xx, 401) are not retried: they will not change
// on a second attempt. Network failures get two more tries before the page shows an error.

import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./client.ts";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failures, error) => !(error instanceof ApiError) && failures < 2,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: false,
    },
  },
});
