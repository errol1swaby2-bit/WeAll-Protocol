import React, { useEffect, useRef, useState } from "react";

import { weall } from "../api/weall";

type MediaLike = any;

function asArray<T = any>(v: any): T[] {
  return Array.isArray(v) ? v : [];
}

function firstString(...vals: any[]): string {
  for (const v of vals) {
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

function deriveCid(item: MediaLike): string {
  if (typeof item === "string") {
    const raw = item.trim();
    if (raw.startsWith("ipfs://")) return raw.slice("ipfs://".length);
    return "";
  }
  if (!item || typeof item !== "object") return "";
  const raw = firstString(
    item.cid,
    item.video_cid,
    item.upload_ref,
    item.ref,
    item.gateway_cid,
    item.ipfs_cid,
    item.hash,
    item.uri,
    item.url,
  );
  if (!raw) return "";
  if (raw.startsWith("ipfs://")) return raw.slice("ipfs://".length);
  const m = raw.match(/\/ipfs\/([^/?#]+)/i);
  if (m?.[1]) return m[1];
  return /^[A-Za-z0-9]+$/.test(raw) ? raw : "";
}

function joinBasePath(base: string, path: string): string {
  const b = String(base || "").replace(/\/+$/, "");
  const p = String(path || "").startsWith("/") ? String(path || "") : `/${String(path || "")}`;
  return `${b || ""}${p}`;
}

function isProxyPath(path: string): boolean {
  const raw = String(path || "").trim();
  if (!raw) return false;
  if (raw.startsWith("/v1/media/proxy/")) return true;
  try {
    const parsed = new URL(raw);
    return parsed.pathname.startsWith("/v1/media/proxy/");
  } catch {
    return false;
  }
}

function deriveExternalUrl(item: MediaLike): string {
  if (typeof item === "string") {
    const raw = item.trim();
    if (/^https?:\/\//i.test(raw) && !deriveCid(raw)) return raw;
    return "";
  }
  if (!item || typeof item !== "object") return "";
  const direct = firstString(item.gateway_url, item.url, item.src, item.href);
  if (/^https?:\/\//i.test(direct) && !deriveCid(direct)) return String(direct);
  return "";
}

function deriveUrl(item: MediaLike, base: string): string {
  const cid = deriveCid(item);
  if (cid) return weall.mediaProxyUrl(cid, base);
  if (!item || typeof item !== "object") return "";

  const fetchPath = firstString(item.fetch_path, item.proxy_path, item.local_proxy_path);
  if (fetchPath && isProxyPath(fetchPath)) {
    if (/^https?:\/\//i.test(fetchPath)) {
      try {
        return joinBasePath(base, new URL(fetchPath).pathname);
      } catch {
        return "";
      }
    }
    return joinBasePath(base, fetchPath);
  }

  // Direct HTTP gateway/provider URLs are intentionally not auto-loaded.
  // The frontend should render media through the local observer proxy whenever a CID exists.
  // If no CID exists, expose only a manual external attachment button.
  return "";
}

function deriveMime(item: MediaLike): string {
  if (!item || typeof item !== "object") return "";
  return firstString(item.mime, item.mime_type, item.content_type, item.type).toLowerCase();
}

function deriveLabel(item: MediaLike): string {
  if (typeof item === "string") return item;
  if (!item || typeof item !== "object") return "Unknown media";
  return firstString(item.name, item.filename, item.label, item.title, item.media_id, item.cid, JSON.stringify(item));
}

function kindFor(item: MediaLike): "image" | "video" | "audio" | "file" {
  const mime = deriveMime(item);
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "audio";

  const url = deriveUrl(item, "").toLowerCase();
  if (/\.(png|jpe?g|gif|webp|svg)$/i.test(url)) return "image";
  if (/\.(mp4|webm|mov|m4v)$/i.test(url)) return "video";
  if (/\.(mp3|wav|ogg|m4a)$/i.test(url)) return "audio";
  return "file";
}

function useViewportLoad(rootMargin = "640px"): [React.RefObject<HTMLDivElement>, boolean] {
  const ref = useRef<HTMLDivElement>(null);
  const [shouldLoad, setShouldLoad] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el || shouldLoad) return;
    if (typeof IntersectionObserver === "undefined") {
      setShouldLoad(true);
      return;
    }
    const obs = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setShouldLoad(true);
          obs.disconnect();
        }
      },
      { root: null, rootMargin, threshold: 0.01 },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [rootMargin, shouldLoad]);

  return [ref, shouldLoad];
}

export function extractEvidenceMedia(evidence: any): MediaLike[] {
  if (!evidence || typeof evidence !== "object") return [];
  const out: MediaLike[] = [];
  for (const [key, value] of Object.entries(evidence)) {
    if (value == null) continue;
    if (typeof value === "string") {
      const lowered = key.toLowerCase();
      if (lowered.includes("cid") || lowered.includes("video") || lowered.includes("uri") || lowered.includes("url")) {
        out.push({ cid: deriveCid(value) || undefined, url: /^https?:\/\//i.test(value) ? value : undefined, label: key, raw: value });
      }
      continue;
    }
    if (Array.isArray(value)) {
      for (const inner of value) out.push(inner);
      continue;
    }
    if (typeof value === "object") out.push({ label: key, ...value });
  }
  return out;
}

function DeferredMediaCard({
  base,
  item,
  title,
  compact,
  idx,
  restrictedPlayback,
  lockAfterMs,
  allowedReplays,
}: {
  base: string;
  item: MediaLike;
  title: string;
  compact: boolean;
  idx: number;
  restrictedPlayback: boolean;
  lockAfterMs: number;
  allowedReplays: number;
}): JSX.Element {
  const [ref, shouldLoad] = useViewportLoad();
  const videoRef = useRef<HTMLVideoElement>(null);
  const lockTimerRef = useRef<number | null>(null);
  const [locked, setLocked] = useState(false);
  const [spent, setSpent] = useState(false);
  const [replaysUsed, setReplaysUsed] = useState(0);
  const [playbackKey, setPlaybackKey] = useState(0);
  const url = deriveUrl(item, base);
  const externalUrl = deriveExternalUrl(item);
  const mime = deriveMime(item);
  const cid = deriveCid(item);
  const label = deriveLabel(item);
  const kind = kindFor(item);
  const restrictedVideo = restrictedPlayback && kind === "video";

  useEffect(() => {
    return () => {
      if (lockTimerRef.current !== null) window.clearTimeout(lockTimerRef.current);
    };
  }, []);

  function clearPlaybackTimer(): void {
    if (lockTimerRef.current !== null) window.clearTimeout(lockTimerRef.current);
    lockTimerRef.current = null;
  }

  function lockRestrictedPlayback(): void {
    clearPlaybackTimer();
    const node = videoRef.current;
    try { node?.pause(); } catch { /* ignore media pause failures */ }
    if (replaysUsed < allowedReplays) setLocked(true);
    else setSpent(true);
  }

  function startRestrictedPlaybackWindow(): void {
    if (!restrictedVideo || locked || spent) return;
    clearPlaybackTimer();
    lockTimerRef.current = window.setTimeout(lockRestrictedPlayback, lockAfterMs);
  }

  function markRestrictedPlaybackEnded(): void {
    if (!restrictedVideo) return;
    lockRestrictedPlayback();
  }

  function rewatchRestrictedPlayback(): void {
    if (!restrictedVideo || replaysUsed >= allowedReplays) return;
    clearPlaybackTimer();
    setReplaysUsed((n) => n + 1);
    setLocked(false);
    setSpent(false);
    setPlaybackKey((n) => n + 1);
  }

  return (
    <div key={`${label}:${idx}`} ref={ref} className="feedMediaCard">
      <div className="feedMediaTitle">{title}</div>
      {!shouldLoad ? (
        <div className="inlineNote" style={{ marginTop: 8 }}>
          Media will load from your local observer when it reaches this part of the feed.
        </div>
      ) : null}
      {kind === "image" && url && shouldLoad ? <img src={url} alt={label} loading="lazy" decoding="async" style={{ width: "100%", borderRadius: 12, maxHeight: compact ? 280 : 360, objectFit: "cover" }} /> : null}
      {kind === "video" && url && shouldLoad && !(restrictedVideo && (locked || spent)) ? (
        <video
          key={playbackKey}
          ref={videoRef}
          src={url}
          controls
          preload="none"
          controlsList={restrictedVideo ? "nodownload noplaybackrate noremoteplayback" : undefined}
          disablePictureInPicture={restrictedVideo || undefined}
          onContextMenu={restrictedVideo ? (event) => event.preventDefault() : undefined}
          onPlay={startRestrictedPlaybackWindow}
          onEnded={markRestrictedPlaybackEnded}
          style={{ width: "100%", borderRadius: 12, maxHeight: compact ? 280 : 360 }}
        />
      ) : null}
      {restrictedVideo && locked ? (
        <div className="inlineNote" style={{ marginTop: 8 }}>
          Evidence playback locked after the review window.
          <div className="buttonRow" style={{ marginTop: 8 }}>
            <button className="btn" type="button" onClick={rewatchRestrictedPlayback}>Rewatch once</button>
          </div>
        </div>
      ) : null}
      {restrictedVideo && spent ? <div className="inlineNote" style={{ marginTop: 8 }}>Evidence playback is locked. The one rewatch allowance has already been used.</div> : null}
      {restrictedVideo ? <div className="feedMediaMeta">Restricted reviewer evidence: playback auto-locks after 5 minutes or when the video ends. Browser controls reduce download/remote-playback exposure, but operating systems and browsers cannot reliably prevent screen recording.</div> : null}
      {kind === "audio" && url && shouldLoad ? <audio src={url} controls preload="none" style={{ width: "100%" }} /> : null}
      {kind === "file" && url ? (
        <a href={url} target="_blank" rel="noreferrer" className="btn" style={{ width: "fit-content" }}>
          Open attachment through observer
        </a>
      ) : null}
      {!url && externalUrl ? (
        <a href={externalUrl} target="_blank" rel="noreferrer" className="btn" style={{ width: "fit-content" }}>
          Open external attachment
        </a>
      ) : null}
      <div className="feedMediaMeta mono" style={{ marginTop: 8 }}>
        {label}
      </div>
      <div className="statusSummary" style={{ marginTop: 8 }}>
        {mime ? <span className="statusPill">{mime}</span> : null}
        {cid ? <span className="statusPill mono">{cid}</span> : null}
        <span className="statusPill">viewport loaded</span>
      </div>
      {!url && !externalUrl ? <div className="cardDesc" style={{ marginTop: 8 }}>Unresolved media reference. The post may only expose a media id at this stage.</div> : null}
      {!url && externalUrl ? <div className="cardDesc" style={{ marginTop: 8 }}>External media is not auto-loaded. Open it manually only if you trust the source.</div> : null}
    </div>
  );
}

export default function MediaGallery({
  base,
  media,
  title = "Media",
  compact = false,
  restrictedPlayback = false,
  lockAfterMs = 5 * 60 * 1000,
  allowedReplays = 1,
}: {
  base: string;
  media: MediaLike[];
  title?: string;
  compact?: boolean;
  restrictedPlayback?: boolean;
  lockAfterMs?: number;
  allowedReplays?: number;
}): JSX.Element | null {
  const items = asArray(media).filter((item) => item != null);
  if (!items.length) return null;

  return (
    <div className="feedMediaList" style={{ gap: compact ? 10 : 12 }}>
      {items.map((item, idx) => (
        <DeferredMediaCard key={`${deriveLabel(item)}:${idx}`} base={base} item={item} title={title} compact={compact} idx={idx} restrictedPlayback={restrictedPlayback} lockAfterMs={lockAfterMs} allowedReplays={allowedReplays} />
      ))}
    </div>
  );
}
