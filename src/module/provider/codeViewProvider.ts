import {
  CancellationToken,
  commands,
  ExtensionContext,
  Uri,
  Webview,
  WebviewView,
  WebviewViewProvider,
  WebviewViewResolveContext,
  window,
  workspace,
} from "vscode";
import { multiStepInput } from "../multiStepInput";
import { getNonce } from "../getNonce";
import { MemFS } from "./fileSystemProvider";

interface IFile {
  path: string;
  children: undefined | IFile[];
}

export default class CodeViewProvider implements WebviewViewProvider {
  public static readonly viewType = "picode.codeview";
  public initialized = false;

  public _view?: WebviewView;

  constructor(
    private readonly _extensionUri: Uri,
    private _context: ExtensionContext,
    private _fileSystem: MemFS,
    private _serverInfo: void | {
      title: string;
      step: number;
      totalSteps: number;
      port: string;
      id: string;
      password: string;
    }
  ) {
    workspace.updateWorkspaceFolders(0, 0, {
      uri: Uri.parse("memfs:/"),
      name: "picode",
    });

    multiStepInput(this._context);
  }

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

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    webviewView.webview.onDidReceiveMessage((data) => {
      console.log(data, "sibal");
      switch (data.type) {
        case "loadProject": {
          for (const [name] of this._fileSystem.readDirectory(
            Uri.parse("memfs:/")
          )) {
            this._fileSystem.delete(Uri.parse(`memfs:/${name}`));
          }

          this._buildFileStructure(data.root);
          break;
        }
        case "selectCode": {
          this.loadProject(data.codeName);
          break;
        }
      }
    });
  }

  public reloadCode() {
    this._view?.webview.postMessage({
      type: "reloadCode",
    });
  }

  public loadProject(codeName: string) {
    setTimeout(() => {
      this._fileSystem.createDirectory(Uri.parse(`memfs:/test/`));

      this._fileSystem.writeFile(
        Uri.parse(`memfs:/test/test.js`),
        Buffer.from("console.log('hello!! this is test code!')"),
        { create: true, overwrite: true }
      );
    }, 1000);
  }

  private _buildFileStructure(file: IFile) {
    if (file.path !== "\\") {
      if (file.children !== undefined) {
        this._fileSystem.createDirectory(
          Uri.parse(`memfs:${file.path.replace(/\\/g, "/")}`)
        );
        file.children.map((v) => {
          this._buildFileStructure(v);
        });
      } else {
        this._fileSystem.writeFile(
          Uri.parse(`memfs:${file.path.replace(/\\/g, "/")}`),
          new Uint8Array(0),
          { create: true, overwrite: true }
        );
      }
    } else {
      (file.children ?? []).map((v) => {
        this._buildFileStructure(v);
      });
    }
  }

  private _getHtmlForWebview(webview: Webview) {
    const styleResetUri = webview.asWebviewUri(
      Uri.joinPath(this._extensionUri, "webview", "constant", "reset.css")
    );

    const styleVSCodeUri = webview.asWebviewUri(
      Uri.joinPath(this._extensionUri, "webview", "constant", "vscode.css")
    );

    const styleMainUri = webview.asWebviewUri(
      Uri.joinPath(this._extensionUri, "webview", "code", "main.css")
    );

    const scriptUri = webview.asWebviewUri(
      Uri.joinPath(this._extensionUri, "webview", "code", "main.js")
    );

    const codiconsUri = webview.asWebviewUri(
      Uri.joinPath(
        this._extensionUri,
        "node_modules",
        "@vscode/codicons",
        "dist",
        "codicon.css"
      )
    );

    const nonce = getNonce();

    return `<!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8" />    
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      
          <link href="${styleResetUri}" rel="stylesheet" />
          <link href="${styleVSCodeUri}" rel="stylesheet" />
          <link href="${styleMainUri}" rel="stylesheet" />
          <link href="${codiconsUri}" rel="stylesheet" />
        </head>
        <body>
          <div id="root">
          
          </div>
  
          <script nonce="${nonce}" src="${scriptUri}"></script>
        </body>
      </html>`;
  }
}
