import {
  CancellationToken,
  Uri,
  Webview,
  WebviewView,
  WebviewViewProvider,
  WebviewViewResolveContext,
} from "vscode";
import { getNonce } from "../getNonce";

export default class CreateProjectProvider implements WebviewViewProvider {
  public static readonly viewType = "picode.editorview";

  private _view?: WebviewView;

  constructor(private readonly _extensionUri: Uri) {}

  public resolveWebviewView(
    webviewView: WebviewView,
    context: WebviewViewResolveContext,
    _token: CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this.getHtmlForWebview(webviewView.webview);
  }

  public getHtmlForWebview(webview: Webview) {
    const styleMainUri = webview.asWebviewUri(
      Uri.joinPath(
        this._extensionUri,
        "webview",
        "createProject",
        "css",
        "main.538f74f5.chunk.css"
      )
    );

    const script1Uri = webview.asWebviewUri(
      Uri.joinPath(
        this._extensionUri,
        "webview",
        "createProject",
        "js",
        "2.25c34183.chunk.js"
      )
    );

    const script2Uri = webview.asWebviewUri(
      Uri.joinPath(
        this._extensionUri,
        "webview",
        "createProject",
        "js",
        "main.33523783.chunk.js"
      )
    );

    const nonce = getNonce();

    return `
          <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width,initial-scale=1.0" />
    
            <link href="${styleMainUri}" rel="stylesheet" />
        </head>
        <body>
            <noscript>You need to enable JavaScript to run this app.</noscript>
            <div id="root"></div>
    
            <script nonce="${nonce}" src="${script1Uri}"></script>
            <script nonce="${nonce}" src="${script2Uri}"></script>
        </body>
        </html>
    `;
  }
}
