/** A browser-facing testnet API target must be a plain HTTPS origin. */
export function isPublicApiOrigin(value: string): boolean {
  try {
    const url = new URL(String(value || "").trim());
    return url.protocol === "https:" &&
      !!url.hostname && !url.username && !url.password &&
      (url.pathname === "/" || url.pathname === "") &&
      !url.search && !url.hash;
  } catch {
    return false;
  }
}
