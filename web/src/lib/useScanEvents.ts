import { useEffect, useState } from "react";
import { ApiError, type ScanEvent } from "../api";

const pollInterval = 1000;

/**
 * Follows a scan's activity log by polling for new lines once a second until
 * the scan finishes. Short requests, unlike a long-lived stream, never use up
 * the browser's few connections to the server when several pages are open.
 */
export function useScanEvents(scanId: string) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [ended, setEnded] = useState(false);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let after = 0;
    setEvents([]);
    setEnded(false);
    setUnavailable(false);

    async function poll() {
      try {
        const response = await fetch(`/api/scans/${scanId}/events?after=${after}`);
        if (response.status === 404) {
          if (!cancelled) setUnavailable(true);
          return;
        }
        if (!response.ok) throw new ApiError(`HTTP ${response.status}`, response.status);
        const page = (await response.json()) as { events: ScanEvent[]; finished: boolean };
        if (cancelled) return;
        if (page.events.length > 0) {
          after = page.events[page.events.length - 1].seq;
          setEvents((current) => [...current, ...page.events]);
        }
        if (page.finished) {
          setEnded(true);
          return;
        }
      } catch {
        // A failed poll is retried on the next tick.
      }
      if (!cancelled) timer = setTimeout(poll, pollInterval);
    }
    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [scanId]);

  return { events, ended, unavailable };
}
