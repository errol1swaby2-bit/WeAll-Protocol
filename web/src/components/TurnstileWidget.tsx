import React, { useEffect, useMemo, useRef, useState } from "react";

declare global {
  interface Window {
    turnstile?: {
      render: (
        el: HTMLElement,
        opts: {
          sitekey: string;
          callback: (token: string) => void;
          "error-callback"?: () => void;
          "expired-callback"?: () => void;
        }
      ) => string;
      reset: (widgetId?: string) => void;
      remove?: (widgetId?: string) => void;
    };
  }
}

function env(k: string): string {
  return ((import.meta as any).env?.[k] as string) || "";
}

function loadTurnstileScript(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (document.querySelector('script[data-weall-turnstile="1"]')) return resolve();

    const s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    s.async = true;
    s.defer = true;
    s.setAttribute("data-weall-turnstile", "1");
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("Failed to load Turnstile script"));
    document.head.appendChild(s);
  });
}

export type TurnstileWidgetProps = {
  onToken: (token: string) => void;
  onError?: () => void;
  onExpired?: () => void;
  className?: string;
  style?: React.CSSProperties;
};

export default function TurnstileWidget(props: TurnstileWidgetProps): JSX.Element {
  const siteKey = useMemo(() => env("VITE_TURNSTILE_SITE_KEY").trim(), []);
  const hostRef = useRef<HTMLDivElement | null>(null);

  const [ready, setReady] = useState(false);
  const widgetIdRef = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      if (!siteKey) {
        setReady(false);
        return;
      }

      await loadTurnstileScript();

      // Wait for window.turnstile
      const start = Date.now();
      while (!window.turnstile) {
        if (Date.now() - start > 4000) throw new Error("Turnstile not available");
        await new Promise((r) => setTimeout(r, 50));
      }

      if (cancelled) return;
      if (!hostRef.current) return;

      // Render widget exactly once per mount.
      widgetIdRef.current = window.turnstile!.render(hostRef.current, {
        sitekey: siteKey,
        callback: (token) => props.onToken(token),
        "error-callback": () => props.onError?.(),
        "expired-callback": () => props.onExpired?.(),
      });

      setReady(true);
    })().catch(() => {
      // keep ready=false
      setReady(false);
      props.onError?.();
    });

    return () => {
      cancelled = true;
      try {
        if (widgetIdRef.current && window.turnstile?.remove) {
          window.turnstile.remove(widgetIdRef.current);
        }
      } catch {
        // ignore
      }
      widgetIdRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function reset(): void {
    try {
      if (widgetIdRef.current && window.turnstile) window.turnstile.reset(widgetIdRef.current);
    } catch {
      // ignore
    }
  }

  // Expose a simple reset hook via DOM dataset (optional, but handy)
  useEffect(() => {
    if (!hostRef.current) return;
    (hostRef.current as any).__weallResetTurnstile = reset;
  }, [ready]);

  if (!siteKey) {
    return (
      <div style={{ padding: 12, border: "1px solid #ccc", borderRadius: 10 }}>
        <b>Turnstile not configured.</b>
        <div style={{ marginTop: 6, fontSize: 12, opacity: 0.8 }}>
          Set <code>VITE_TURNSTILE_SITE_KEY</code> in your env file.
        </div>
      </div>
    );
  }

  return (
    <div className={props.className} style={props.style}>
      <div ref={hostRef} />
      {!ready && <div style={{ marginTop: 8, fontSize: 12, opacity: 0.7 }}>Loading Turnstile…</div>}
    </div>
  );
}
