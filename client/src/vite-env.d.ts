/// <reference types="vite/client" />

/** true in the browser build (`vite --mode web`), false in the Tauri app. Set by vite.config.ts. */
declare const __WEB__: boolean;

interface ImportMetaEnv {
  /**
   * Server the connect dialog starts with, "host" or "host:port". Set at build
   * time to hand out a demo build pointing at a public relay; unset in the
   * normal release, where the dialog falls back to the page origin (web) or
   * localhost (desktop). See BUILDING.md.
   */
  readonly VITE_DEFAULT_SERVER?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
