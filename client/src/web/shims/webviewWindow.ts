// Web replacement for @tauri-apps/api/webviewWindow (the screen-share pop-out
// is hidden on web, so no window is ever opened).

import { Window } from "./window";

export class WebviewWindow extends Window {
  constructor(_label: string, _options?: Record<string, unknown>) {
    super();
  }
}
