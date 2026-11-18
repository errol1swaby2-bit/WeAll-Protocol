// Build contract retained for existing VITE_WEALL_* public variable names.
interface ImportMetaEnv {
  readonly PROD: boolean;
  readonly DEV: boolean;
  readonly MODE: string;
  readonly BASE_URL: string;
  readonly SSR: boolean;
  readonly [key: `VITE_${string}`]: string | undefined;
}
interface ImportMeta { readonly env: ImportMetaEnv }
declare module "*.css";
declare module "*.svg" { const url: string; export default url; }
declare module "*.png" { const url: string; export default url; }
declare module "*.jpg" { const url: string; export default url; }
declare module "*.webp" { const url: string; export default url; }
