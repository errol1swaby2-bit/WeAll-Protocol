import React from "react";

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

function deriveUrl(item: MediaLike, base: string): string {
  if (typeof item === "string") {
    const raw = item.trim();
    if (/^https?:\/\//i.test(raw)) return raw;
    const cid = deriveCid(raw);
    return cid ? weall.mediaGatewayUrl(cid, base) : "";
  }
  if (!item || typeof item !== "object") return "";
  const direct = firstString(item.gateway_url, item.url, item.src, item.href);
  if (direct) {
    if (/^https?:\/\//i.test(direct)) return direct;
    if (direct.startsWith("ipfs://")) return weall.mediaGatewayUrl(direct.slice("ipfs://".length), base);
  }
  const cid = deriveCid(item);
  return cid ? weall.mediaGatewayUrl(cid, base) : "";
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

export default function MediaGallery({
  base,
  media,
  title = "Media",
  compact = false,
}: {
  base: string;
  media: MediaLike[];
  title?: string;
  compact?: boolean;
}): JSX.Element | null {
  const items = asArray(media).filter((item) => item != null);
  if (!items.length) return null;

  return (
    <div className="feedMediaList" style={{ gap: compact ? 10 : 12 }}>
      {items.map((item, idx) => {
        const url = deriveUrl(item, base);
        const mime = deriveMime(item);
        const cid = deriveCid(item);
        const label = deriveLabel(item);
        const kind = kindFor(item);

        return (
          <div key={`${label}:${idx}`} className="feedMediaCard">
            <div className="feedMediaTitle">{title}</div>
            {kind === "image" && url ? <img src={url} alt={label} style={{ width: "100%", borderRadius: 12, maxHeight: 360, objectFit: "cover" }} /> : null}
            {kind === "video" && url ? <video src={url} controls style={{ width: "100%", borderRadius: 12, maxHeight: 360 }} /> : null}
            {kind === "audio" && url ? <audio src={url} controls style={{ width: "100%" }} /> : null}
            {kind === "file" && url ? (
              <a href={url} target="_blank" rel="noreferrer" className="btn" style={{ width: "fit-content" }}>
                Open attachment
              </a>
            ) : null}
            <div className="feedMediaMeta mono" style={{ marginTop: 8 }}>
              {label}
            </div>
            <div className="statusSummary" style={{ marginTop: 8 }}>
              {mime ? <span className="statusPill">{mime}</span> : null}
              {cid ? <span className="statusPill mono">{cid}</span> : null}
            </div>
            {!url ? <div className="cardDesc" style={{ marginTop: 8 }}>Unresolved media reference. The post may only expose a media id at this stage.</div> : null}
          </div>
        );
      })}
    </div>
  );
}
