// web/src/lib/version.ts

// These are injected by Vite define in vite.config.ts.
// Fallbacks keep dev environments functional if the define step is bypassed.

declare const __WEALL_WEB_VERSION__: string | undefined;
declare const __WEALL_WEB_GIT_SHA__: string | undefined;

export function webVersion(): string {
  const v = typeof __WEALL_WEB_VERSION__ === "string" ? __WEALL_WEB_VERSION__ : "";
  return v || "0.0.0";
}

export function webGitSha(): string {
  const s = typeof __WEALL_WEB_GIT_SHA__ === "string" ? __WEALL_WEB_GIT_SHA__ : "";
  return s || "nogit";
}

export function webBuildLabel(): string {
  return `${webVersion()}+${webGitSha()}`;
}
