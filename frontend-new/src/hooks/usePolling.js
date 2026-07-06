import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * Generic polling hook.
 * Calls `fetchFn()` every `intervalMs`, stops when `stopWhen(data)` returns true.
 */
export function usePolling(fetchFn, { intervalMs = 3000, stopWhen = () => false } = {}) {
  const [data, setData]     = useState(null);
  const [error, setError]   = useState(null);
  const [loading, setLoading] = useState(true);
  const timerRef = useRef(null);
  const stoppedRef = useRef(false);

  const poll = useCallback(async () => {
    try {
      const result = await fetchFn();
      setData(result);
      setError(null);
      setLoading(false);
      if (stopWhen(result)) {
        stoppedRef.current = true;
        return;
      }
    } catch (err) {
      setError(err);
      setLoading(false);
    }
    if (!stoppedRef.current) {
      timerRef.current = setTimeout(poll, intervalMs);
    }
  }, [fetchFn, intervalMs, stopWhen]);

  useEffect(() => {
    stoppedRef.current = false;
    poll();
    return () => {
      stoppedRef.current = true;
      clearTimeout(timerRef.current);
    };
  }, [poll]);

  return { data, error, loading };
}
