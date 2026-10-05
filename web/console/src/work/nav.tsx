import { useNavigate } from "@tanstack/react-router";
import type { ReactNode } from "react";

type Go = (
  to: string,
  options?: { replace?: boolean; search?: Readonly<Record<string, string | undefined>> },
) => void;

/** Router navigation by concrete path. The route tree validates every path it is given. */
export function useGo(): Go {
  const navigate = useNavigate();
  return (to, options) => void navigate({ to, ...options } as never);
}

function plainClick(event: {
  button: number;
  metaKey: boolean;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
}): boolean {
  return !(event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey);
}

/** A real link (new tab, copy address) whose plain click goes through the router. */
export function RouteLink({
  to,
  search,
  children,
  label,
}: {
  to: string;
  search?: Readonly<Record<string, string | undefined>>;
  children: ReactNode;
  label?: string;
}) {
  const go = useGo();
  const query = search
    ? `?${new URLSearchParams(
        Object.entries(search).filter((entry): entry is [string, string] => entry[1] !== undefined),
      ).toString()}`
    : "";
  return (
    <a
      href={`${to}${query === "?" ? "" : query}`}
      aria-label={label}
      onClick={(event) => {
        if (!plainClick(event)) return;
        event.preventDefault();
        go(to, { search });
      }}
    >
      {children}
    </a>
  );
}
