// Small hooks of the site pages.

import { useEffect, useState } from "react";

/** The value as it was `delay` milliseconds after it last changed (docs/06 6.4.9: impact after 600 ms). */
export function useDebounced<T>(value: T, delay: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return settled;
}
