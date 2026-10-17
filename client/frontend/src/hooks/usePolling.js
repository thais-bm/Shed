import { useEffect } from "react";

export function usePolling(callback, interval, enabled = true) {
  useEffect(() => {
    if (!enabled) return undefined;
    const timer = window.setInterval(callback, interval);
    return () => window.clearInterval(timer);
  }, [callback, enabled, interval]);
}
