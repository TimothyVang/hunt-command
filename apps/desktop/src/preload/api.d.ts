import type { DesktopBridge } from "../shared/ipc.ts";

declare global {
  interface Window {
    huntWorkbench?: DesktopBridge;
  }
}

export {};
