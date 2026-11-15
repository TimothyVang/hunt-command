/**
 * Sandboxed Hidden Chromium `printToPDF` Renderer for Customer Reports.
 *
 * Opens a zero-JS, zero-egress hidden `BrowserWindow` (`sandbox: true`, `contextIsolation: true`,
 * `nodeIntegration: false`, `javascript: false`), renders the escaped report HTML, prints to PDF,
 * and destroys the window immediately.
 */
import { BrowserWindow, session } from "electron";
import { buildDeterministicFallbackPdf } from "./report-exporter.ts";

let printSeq = 0;

export async function renderHtmlToPdfViaChromium(
  printHtml: string,
  fallbackMarkdown: string,
): Promise<Uint8Array> {
  const partition = `hunt-pdf-export:${++printSeq}`;
  const ses = session.fromPartition(partition, { cache: false });
  await ses.setProxy({ proxyRules: "http://127.0.0.1:1", proxyBypassRules: "<-loopback>" });
  ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  ses.on("will-download", (ev) => ev.preventDefault());

  const win = new BrowserWindow({
    show: false,
    width: 1024,
    height: 1320,
    webPreferences: {
      session: ses,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      javascript: false,
      webSecurity: true,
      offscreen: true,
    },
  });

  try {
    win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    const dataUrl = `data:text/html;charset=utf-8,${encodeURIComponent(printHtml)}`;
    await win.loadURL(dataUrl);
    const pdfBuffer = await win.webContents.printToPDF({
      printBackground: true,
      pageSize: "Letter",
      margins: {
        top: 0.4,
        bottom: 0.4,
        left: 0.4,
        right: 0.4,
      },
    });
    return new Uint8Array(pdfBuffer);
  } catch {
    return buildDeterministicFallbackPdf("Hunt Command DFIR Report", fallbackMarkdown);
  } finally {
    if (!win.isDestroyed()) {
      win.destroy();
    }
  }
}
