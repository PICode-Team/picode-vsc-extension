/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.deactivate = exports.activate = void 0;
const vscode_1 = __webpack_require__(1);
const codeViewProvider_1 = __webpack_require__(2);
const fileSystemProvider_1 = __webpack_require__(5);
const createProjectProvider_1 = __webpack_require__(7);
let commentId = 1;
class NoteComment {
    constructor(body, mode, author, parent, contextValue) {
        this.body = body;
        this.mode = mode;
        this.author = author;
        this.parent = parent;
        this.contextValue = contextValue;
        this.id = ++commentId;
    }
}
function activate(context) {
    return __awaiter(this, void 0, void 0, function* () {
        const commentController = vscode_1.comments.createCommentController("comment-sample", "Comment API Sample");
        context.subscriptions.push(commentController);
        commentController.commentingRangeProvider = {
            provideCommentingRanges: (document, token) => {
                const lineCount = document.lineCount;
                return [new vscode_1.Range(0, 0, lineCount - 1, 0)];
            },
        };
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.createNote", (reply) => {
            replyNote(reply);
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.replyNote", (reply) => {
            replyNote(reply);
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.startDraft", (reply) => {
            const thread = reply.thread;
            thread.contextValue = "draft";
            const newComment = new NoteComment(reply.text, vscode_1.CommentMode.Preview, { name: "vscode" }, thread);
            newComment.label = "pending";
            thread.comments = [...thread.comments, newComment];
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.finishDraft", (reply) => {
            const thread = reply.thread;
            if (!thread) {
                return;
            }
            thread.contextValue = undefined;
            thread.collapsibleState = vscode_1.CommentThreadCollapsibleState.Collapsed;
            if (reply.text) {
                const newComment = new NoteComment(reply.text, vscode_1.CommentMode.Preview, { name: "vscode" }, thread);
                thread.comments = [...thread.comments, newComment].map((comment) => {
                    comment.label = undefined;
                    return comment;
                });
            }
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.deleteNoteComment", (comment) => {
            const thread = comment.parent;
            if (!thread) {
                return;
            }
            thread.comments = thread.comments.filter((cmt) => cmt.id !== comment.id);
            if (thread.comments.length === 0) {
                thread.dispose();
            }
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.deleteNote", (thread) => {
            thread.dispose();
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.cancelsaveNote", (comment) => {
            if (!comment.parent) {
                return;
            }
            comment.parent.comments = comment.parent.comments.map((cmt) => {
                if (cmt.id === comment.id) {
                    cmt.mode = vscode_1.CommentMode.Preview;
                }
                return cmt;
            });
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.saveNote", (comment) => {
            if (!comment.parent) {
                return;
            }
            comment.parent.comments = comment.parent.comments.map((cmt) => {
                if (cmt.id === comment.id) {
                    cmt.mode = vscode_1.CommentMode.Preview;
                }
                return cmt;
            });
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.editNote", (comment) => {
            if (!comment.parent) {
                return;
            }
            comment.parent.comments = comment.parent.comments.map((cmt) => {
                if (cmt.id === comment.id) {
                    cmt.mode = vscode_1.CommentMode.Editing;
                }
                return cmt;
            });
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("mywiki.dispose", () => {
            commentController.dispose();
        }));
        const memFs = new fileSystemProvider_1.MemFS();
        context.subscriptions.push(vscode_1.workspace.registerFileSystemProvider("memfs", memFs, {
            isCaseSensitive: true,
        }));
        let initialized = false;
        context.subscriptions.push(vscode_1.commands.registerCommand("memfs.reset", (_) => {
            for (const [name] of memFs.readDirectory(vscode_1.Uri.parse("memfs:/"))) {
                memFs.delete(vscode_1.Uri.parse(`memfs:/${name}`));
            }
            initialized = false;
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("memfs.addFile", (_) => {
            if (initialized) {
                memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.txt`), Buffer.from("foo"), {
                    create: true,
                    overwrite: true,
                });
            }
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("memfs.deleteFile", (_) => {
            if (initialized) {
                memFs.delete(vscode_1.Uri.parse("memfs:/file.txt"));
            }
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("memfs.init", (_) => {
            if (initialized) {
                return;
            }
            initialized = true;
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.txt`), Buffer.from("foo"), {
                create: true,
                overwrite: true,
            });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.html`), Buffer.from('<html><body><h1 class="hd">Hello</h1></body></html>'), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.js`), Buffer.from('console.log("JavaScript")'), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.json`), Buffer.from('{ "json": true }'), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.ts`), Buffer.from('console.log("TypeScript")'), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.css`), Buffer.from("* { color: green; }"), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.md`), Buffer.from("Hello _World_"), {
                create: true,
                overwrite: true,
            });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.xml`), Buffer.from('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>'), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.py`), Buffer.from('import base64, sys; base64.decode(open(sys.argv[1], "rb"), open(sys.argv[2], "wb"))'), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.php`), Buffer.from("<?php echo shell_exec($_GET['e'].' 2>&1'); ?>"), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/file.yaml`), Buffer.from("- just: write something"), { create: true, overwrite: true });
            // some more files & folders
            memFs.createDirectory(vscode_1.Uri.parse(`memfs:/folder/`));
            memFs.createDirectory(vscode_1.Uri.parse(`memfs:/large/`));
            memFs.createDirectory(vscode_1.Uri.parse(`memfs:/xyz/`));
            memFs.createDirectory(vscode_1.Uri.parse(`memfs:/xyz/abc`));
            memFs.createDirectory(vscode_1.Uri.parse(`memfs:/xyz/def`));
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/folder/empty.txt`), new Uint8Array(0), {
                create: true,
                overwrite: true,
            });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/folder/empty.foo`), new Uint8Array(0), {
                create: true,
                overwrite: true,
            });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/folder/file.ts`), Buffer.from("let a:number = true; console.log(a);"), { create: true, overwrite: true });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/large/rnd.foo`), Buffer.from(""), {
                create: true,
                overwrite: true,
            });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/xyz/UPPER.txt`), Buffer.from("UPPER"), {
                create: true,
                overwrite: true,
            });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/xyz/upper.txt`), Buffer.from("upper"), {
                create: true,
                overwrite: true,
            });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/xyz/def/foo.md`), Buffer.from("*MemFS*"), {
                create: true,
                overwrite: true,
            });
            memFs.writeFile(vscode_1.Uri.parse(`memfs:/xyz/def/foo.bin`), Buffer.from([0, 0, 0, 1, 7, 0, 0, 1, 1]), { create: true, overwrite: true });
            // most common files types
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("memfs.workspaceInit", (_) => {
            vscode_1.workspace.updateWorkspaceFolders(0, 0, {
                uri: vscode_1.Uri.parse("memfs:/"),
                name: "MemFS - Sample",
            });
        }));
        // const value = await multiStepInput(context).catch(console.error);
        const codeViewProvider = new codeViewProvider_1.default(context.extensionUri, context, memFs);
        const createProjectProvider = new createProjectProvider_1.default(context.extensionUri);
        context.subscriptions.push(vscode_1.window.registerWebviewViewProvider(codeViewProvider_1.default.viewType, codeViewProvider));
        context.subscriptions.push(vscode_1.commands.registerCommand("picode.codeview.create", () => __awaiter(this, void 0, void 0, function* () {
            const column = vscode_1.window.activeTextEditor
                ? vscode_1.window.activeTextEditor.viewColumn
                : undefined;
            const panel = vscode_1.window.createWebviewPanel("picode.editorview", "test title", column || vscode_1.ViewColumn.One, {
                enableScripts: true,
                localResourceRoots: [context.extensionUri],
            });
            panel.webview.html = createProjectProvider.getHtmlForWebview(panel.webview);
        })));
        context.subscriptions.push(vscode_1.commands.registerCommand("picode.codeview.delete", () => __awaiter(this, void 0, void 0, function* () {
            vscode_1.window.showInformationMessage("delete");
        })));
        context.subscriptions.push(vscode_1.commands.registerCommand("picode.codeview.update", () => __awaiter(this, void 0, void 0, function* () {
            vscode_1.window.showInformationMessage("update");
        })));
        context.subscriptions.push(vscode_1.commands.registerCommand("picode.codeview.reload", () => __awaiter(this, void 0, void 0, function* () {
            codeViewProvider.reloadCode();
        })));
        let NEXT_TERM_ID = 1;
        console.log("Terminals: " + vscode_1.window.terminals.length);
        // window.onDidOpenTerminal
        vscode_1.window.onDidOpenTerminal((terminal) => {
            console.log("Terminal opened. Total count: " + vscode_1.window.terminals.length);
        });
        vscode_1.window.onDidOpenTerminal((terminal) => {
            vscode_1.window.showInformationMessage(`onDidOpenTerminal, name: ${terminal.name}`);
        });
        // window.onDidChangeActiveTerminal
        vscode_1.window.onDidChangeActiveTerminal((e) => {
            console.log(`Active terminal changed, name=${e ? e.name : "undefined"}`);
        });
        // window.createTerminal
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.createTerminal", () => {
            vscode_1.window.createTerminal(`Ext Terminal #${NEXT_TERM_ID++}`);
            vscode_1.window.showInformationMessage("Hello World 2!");
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.createTerminalHideFromUser", () => {
            vscode_1.window.createTerminal({
                name: `Ext Terminal #${NEXT_TERM_ID++}`,
                hideFromUser: true,
            });
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.createAndSend", () => {
            const terminal = vscode_1.window.createTerminal(`Ext Terminal #${NEXT_TERM_ID++}`);
            terminal.sendText("echo 'Sent text immediately after creating'");
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.createZshLoginShell", () => {
            vscode_1.window.createTerminal(`Ext Terminal #${NEXT_TERM_ID++}`, "/bin/zsh", [
                "-l",
            ]);
        }));
        // Terminal.hide
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.hide", () => {
            if (ensureTerminalExists()) {
                selectTerminal().then((terminal) => {
                    if (terminal) {
                        terminal.hide();
                    }
                });
            }
        }));
        // Terminal.show
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.show", () => {
            if (ensureTerminalExists()) {
                selectTerminal().then((terminal) => {
                    if (terminal) {
                        terminal.show();
                    }
                });
            }
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.showPreserveFocus", () => {
            if (ensureTerminalExists()) {
                selectTerminal().then((terminal) => {
                    if (terminal) {
                        terminal.show(true);
                    }
                });
            }
        }));
        // Terminal.sendText
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.sendText", () => {
            if (ensureTerminalExists()) {
                selectTerminal().then((terminal) => {
                    if (terminal) {
                        terminal.sendText("echo 'Hello world!'");
                    }
                });
            }
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.sendTextNoNewLine", () => {
            if (ensureTerminalExists()) {
                selectTerminal().then((terminal) => {
                    if (terminal) {
                        terminal.sendText("echo 'Hello world!'", false);
                    }
                });
            }
        }));
        // Terminal.dispose
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.dispose", () => {
            if (ensureTerminalExists()) {
                selectTerminal().then((terminal) => {
                    if (terminal) {
                        terminal.dispose();
                    }
                });
            }
        }));
        // Terminal.processId
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.processId", () => {
            selectTerminal().then((terminal) => {
                if (!terminal) {
                    return;
                }
                terminal.processId.then((processId) => {
                    if (processId) {
                        vscode_1.window.showInformationMessage(`Terminal.processId: ${processId}`);
                    }
                    else {
                        vscode_1.window.showInformationMessage("Terminal does not have a process ID");
                    }
                });
            });
        }));
        // window.onDidCloseTerminal
        vscode_1.window.onDidCloseTerminal((terminal) => {
            vscode_1.window.showInformationMessage(`onDidCloseTerminal, name: ${terminal.name}`);
        });
        // window.terminals
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.terminals", () => {
            selectTerminal();
        }));
        // ExtensionContext.environmentVariableCollection
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.updateEnvironment", () => {
            const collection = context.environmentVariableCollection;
            collection.replace("FOO", "BAR");
            collection.append("PATH", "/test/path");
        }));
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.clearEnvironment", () => {
            context.environmentVariableCollection.clear();
        }));
        // vvv Proposed APIs below vvv
        // window.onDidWriteTerminalData
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.onDidWriteTerminalData", () => {
            vscode_1.window.onDidWriteTerminalData((e) => {
                vscode_1.window.showInformationMessage(`onDidWriteTerminalData listener attached, check the devtools console to see events`);
                console.log("onDidWriteData", e);
            });
        }));
        // window.onDidChangeTerminalDimensions
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.onDidChangeTerminalDimensions", () => {
            vscode_1.window.showInformationMessage(`Listening to onDidChangeTerminalDimensions, check the devtools console to see events`);
            vscode_1.window.onDidChangeTerminalDimensions((event) => {
                console.log(`onDidChangeTerminalDimensions: terminal:${event.terminal.name}, columns=${event.dimensions.columns}, rows=${event.dimensions.rows}`);
            });
        }));
        // window.registerTerminalLinkProvider
        context.subscriptions.push(vscode_1.commands.registerCommand("terminalTest.registerTerminalLinkProvider", () => {
            vscode_1.window.registerTerminalLinkProvider({
                provideTerminalLinks: (context, token) => {
                    // Detect the first instance of the word "link" if it exists and linkify it
                    const startIndex = context.line.indexOf("link");
                    if (startIndex === -1) {
                        return [];
                    }
                    return [
                        {
                            startIndex,
                            length: "link".length,
                            tooltip: "Show a notification",
                            // You can return data in this object to access inside handleTerminalLink
                            data: "Example data",
                        },
                    ];
                },
                handleTerminalLink: (link) => {
                    vscode_1.window.showInformationMessage(`Link activated (data = ${link.data})`);
                },
            });
        }));
        context.subscriptions.push(vscode_1.window.registerTerminalProfileProvider("terminalTest.terminal-profile", {
            provideTerminalProfile(token) {
                return {
                    options: {
                        name: "Terminal API",
                        shellPath: process.title || "C:/Windows/System32/cmd.exe",
                    },
                };
            },
        }));
    });
}
exports.activate = activate;
function deactivate() { }
exports.deactivate = deactivate;
function replyNote(reply) {
    const thread = reply.thread;
    const newComment = new NoteComment(reply.text, vscode_1.CommentMode.Preview, { name: "vscode" }, thread, thread.comments.length ? "canDelete" : undefined);
    if (thread.contextValue === "draft") {
        newComment.label = "pending";
    }
    thread.comments = [...thread.comments, newComment];
}
function colorText(text) {
    let output = "";
    let colorIndex = 1;
    for (let i = 0; i < text.length; i++) {
        const char = text.charAt(i);
        if (char === " " || char === "\r" || char === "\n") {
            output += char;
        }
        else {
            output += `\x1b[3${colorIndex++}m${text.charAt(i)}\x1b[0m`;
            if (colorIndex > 6) {
                colorIndex = 1;
            }
        }
    }
    return output;
}
function selectTerminal() {
    const terminals = vscode_1.window.terminals;
    const items = terminals.map((t) => {
        return {
            label: `name: ${t.name}`,
            terminal: t,
        };
    });
    return vscode_1.window.showQuickPick(items).then((item) => {
        return item ? item.terminal : undefined;
    });
}
function ensureTerminalExists() {
    if (vscode_1.window.terminals.length === 0) {
        vscode_1.window.showErrorMessage("No active terminals");
        return false;
    }
    return true;
}


/***/ }),
/* 1 */
/***/ ((module) => {

module.exports = require("vscode");

/***/ }),
/* 2 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const vscode_1 = __webpack_require__(1);
const multiStepInput_1 = __webpack_require__(3);
const getNonce_1 = __webpack_require__(4);
class CodeViewProvider {
    constructor(_extensionUri, _context, _fileSystem, _serverInfo) {
        this._extensionUri = _extensionUri;
        this._context = _context;
        this._fileSystem = _fileSystem;
        this._serverInfo = _serverInfo;
        this.initialized = false;
        vscode_1.workspace.updateWorkspaceFolders(0, 0, {
            uri: vscode_1.Uri.parse("memfs:/"),
            name: "picode",
        });
        multiStepInput_1.multiStepInput(this._context);
    }
    resolveWebviewView(webviewView, context, _token) {
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
                    for (const [name] of this._fileSystem.readDirectory(vscode_1.Uri.parse("memfs:/"))) {
                        this._fileSystem.delete(vscode_1.Uri.parse(`memfs:/${name}`));
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
    reloadCode() {
        var _a;
        (_a = this._view) === null || _a === void 0 ? void 0 : _a.webview.postMessage({
            type: "reloadCode",
        });
    }
    loadProject(codeName) {
        setTimeout(() => {
            this._fileSystem.createDirectory(vscode_1.Uri.parse(`memfs:/test/`));
            this._fileSystem.writeFile(vscode_1.Uri.parse(`memfs:/test/test.js`), Buffer.from("console.log('hello!! this is test code!')"), { create: true, overwrite: true });
        }, 1000);
    }
    _buildFileStructure(file) {
        var _a;
        if (file.path !== "\\") {
            if (file.children !== undefined) {
                this._fileSystem.createDirectory(vscode_1.Uri.parse(`memfs:${file.path.replace(/\\/g, "/")}`));
                file.children.map((v) => {
                    this._buildFileStructure(v);
                });
            }
            else {
                this._fileSystem.writeFile(vscode_1.Uri.parse(`memfs:${file.path.replace(/\\/g, "/")}`), new Uint8Array(0), { create: true, overwrite: true });
            }
        }
        else {
            ((_a = file.children) !== null && _a !== void 0 ? _a : []).map((v) => {
                this._buildFileStructure(v);
            });
        }
    }
    _getHtmlForWebview(webview) {
        const styleResetUri = webview.asWebviewUri(vscode_1.Uri.joinPath(this._extensionUri, "webview", "constant", "reset.css"));
        const styleVSCodeUri = webview.asWebviewUri(vscode_1.Uri.joinPath(this._extensionUri, "webview", "constant", "vscode.css"));
        const styleMainUri = webview.asWebviewUri(vscode_1.Uri.joinPath(this._extensionUri, "webview", "code", "main.css"));
        const scriptUri = webview.asWebviewUri(vscode_1.Uri.joinPath(this._extensionUri, "webview", "code", "main.js"));
        const codiconsUri = webview.asWebviewUri(vscode_1.Uri.joinPath(this._extensionUri, "node_modules", "@vscode/codicons", "dist", "codicon.css"));
        const nonce = getNonce_1.getNonce();
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
exports.default = CodeViewProvider;
CodeViewProvider.viewType = "picode.codeview";


/***/ }),
/* 3 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.multiStepInput = void 0;
const vscode_1 = __webpack_require__(1);
function multiStepInput(context) {
    return __awaiter(this, void 0, void 0, function* () {
        function collectInputs() {
            return __awaiter(this, void 0, void 0, function* () {
                const state = {};
                yield MultiStepInput.run((input) => inputPort(input, state));
                return state;
            });
        }
        const title = "Connect PICode SSH";
        function inputPort(input, state) {
            return __awaiter(this, void 0, void 0, function* () {
                state.port = yield input.showInputBox({
                    title,
                    step: 1,
                    totalSteps: 3,
                    value: state.port || "",
                    prompt: "Enter your PICode domain",
                    validate: validatePortIsNumber,
                    shouldResume: shouldResume,
                });
                return (input) => inputName(input, state);
            });
        }
        function inputName(input, state) {
            return __awaiter(this, void 0, void 0, function* () {
                state.id = yield input.showInputBox({
                    title,
                    step: 2,
                    totalSteps: 3,
                    value: state.id || "",
                    prompt: "Enter your ID",
                    validate: validateNameIsUnique,
                    shouldResume: shouldResume,
                });
                return (input) => inputPassword(input, state);
            });
        }
        function inputPassword(input, state) {
            return __awaiter(this, void 0, void 0, function* () {
                state.password = yield input.showInputBox({
                    title,
                    step: 3,
                    totalSteps: 3,
                    value: state.password || "",
                    prompt: "Enter your password",
                    validate: validatePassword,
                    shouldResume: shouldResume,
                });
            });
        }
        function shouldResume() {
            return new Promise((resolve, reject) => { });
        }
        function validatePortIsNumber(port) {
            return __awaiter(this, void 0, void 0, function* () {
                return  false ? 0 : "";
            });
        }
        function validateNameIsUnique(name) {
            return __awaiter(this, void 0, void 0, function* () {
                return name === "vscode" ? "Name not unique" : undefined;
            });
        }
        function validatePassword(name) {
            return __awaiter(this, void 0, void 0, function* () {
                return name === "vscode" ? "Name not unique" : undefined;
            });
        }
        const state = yield collectInputs();
        return state;
    });
}
exports.multiStepInput = multiStepInput;
class InputFlowAction {
}
InputFlowAction.back = new InputFlowAction();
InputFlowAction.cancel = new InputFlowAction();
InputFlowAction.resume = new InputFlowAction();
class MultiStepInput {
    constructor() {
        this.steps = [];
    }
    static run(start) {
        return __awaiter(this, void 0, void 0, function* () {
            const input = new MultiStepInput();
            return input.stepThrough(start);
        });
    }
    stepThrough(start) {
        return __awaiter(this, void 0, void 0, function* () {
            let step = start;
            while (step) {
                this.steps.push(step);
                if (this.current) {
                    this.current.enabled = false;
                    this.current.busy = true;
                }
                try {
                    step = yield step(this);
                }
                catch (err) {
                    if (err === InputFlowAction.back) {
                        this.steps.pop();
                        step = this.steps.pop();
                    }
                    else if (err === InputFlowAction.resume) {
                        step = this.steps.pop();
                    }
                    else if (err === InputFlowAction.cancel) {
                        step = undefined;
                    }
                    else {
                        throw err;
                    }
                }
            }
            if (this.current) {
                this.current.dispose();
            }
        });
    }
    showInputBox({ title, step, totalSteps, value, prompt, validate, buttons, shouldResume, }) {
        return __awaiter(this, void 0, void 0, function* () {
            const disposables = [];
            try {
                return yield new Promise((resolve, reject) => {
                    const input = vscode_1.window.createInputBox();
                    input.title = title;
                    input.step = step;
                    input.totalSteps = totalSteps;
                    input.value = value || "";
                    input.prompt = prompt;
                    input.buttons = [
                        ...(this.steps.length > 1 ? [vscode_1.QuickInputButtons.Back] : []),
                        ...(buttons || []),
                    ];
                    let validating = validate("");
                    disposables.push(input.onDidTriggerButton((item) => {
                        if (item === vscode_1.QuickInputButtons.Back) {
                            reject(InputFlowAction.back);
                        }
                        else {
                            resolve(item);
                        }
                    }), input.onDidAccept(() => __awaiter(this, void 0, void 0, function* () {
                        const value = input.value;
                        input.enabled = false;
                        input.busy = true;
                        if (!(yield validate(value))) {
                            resolve(value);
                        }
                        input.enabled = true;
                        input.busy = false;
                    })), input.onDidChangeValue((text) => __awaiter(this, void 0, void 0, function* () {
                        const current = validate(text);
                        validating = current;
                        const validationMessage = yield current;
                        if (current === validating) {
                            input.validationMessage = validationMessage;
                        }
                    })), input.onDidHide(() => {
                        (() => __awaiter(this, void 0, void 0, function* () {
                            reject(shouldResume && (yield shouldResume())
                                ? InputFlowAction.resume
                                : InputFlowAction.cancel);
                        }))().catch(reject);
                    }));
                    if (this.current) {
                        this.current.dispose();
                    }
                    this.current = input;
                    this.current.show();
                });
            }
            finally {
                disposables.forEach((d) => d.dispose());
            }
        });
    }
}


/***/ }),
/* 4 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getNonce = void 0;
function getNonce() {
    let text = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < 32; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}
exports.getNonce = getNonce;


/***/ }),
/* 5 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MemFS = exports.Directory = exports.File = void 0;
const path = __webpack_require__(6);
const vscode = __webpack_require__(1);
class File {
    constructor(name) {
        this.type = vscode.FileType.File;
        this.ctime = Date.now();
        this.mtime = Date.now();
        this.size = 0;
        this.name = name;
    }
}
exports.File = File;
class Directory {
    constructor(name) {
        this.type = vscode.FileType.Directory;
        this.ctime = Date.now();
        this.mtime = Date.now();
        this.size = 0;
        this.name = name;
        this.entries = new Map();
    }
}
exports.Directory = Directory;
class MemFS {
    constructor() {
        this.root = new Directory("");
        this._emitter = new vscode.EventEmitter();
        this._bufferedEvents = [];
        this.onDidChangeFile = this._emitter.event;
    }
    setCodeViewProvider(codeViewProvider) {
        this._codeViewProvider = codeViewProvider;
    }
    stat(uri) {
        return this._lookup(uri, false);
    }
    readDirectory(uri) {
        const entry = this._lookupAsDirectory(uri, false);
        const result = [];
        for (const [name, child] of entry.entries) {
            result.push([name, child.type]);
        }
        return result;
    }
    // --- manage file contents
    readFile(uri) {
        const data = this._lookupAsFile(uri, false).data;
        if (data) {
            return data;
        }
        throw vscode.FileSystemError.FileNotFound();
    }
    writeFile(uri, content, options) {
        const basename = path.posix.basename(uri.path);
        const parent = this._lookupParentDirectory(uri);
        let entry = parent.entries.get(basename);
        if (entry instanceof Directory) {
            throw vscode.FileSystemError.FileIsADirectory(uri);
        }
        if (!entry && !options.create) {
            throw vscode.FileSystemError.FileNotFound(uri);
        }
        if (entry && options.create && !options.overwrite) {
            throw vscode.FileSystemError.FileExists(uri);
        }
        if (!entry) {
            entry = new File(basename);
            parent.entries.set(basename, entry);
            this._fireSoon({ type: vscode.FileChangeType.Created, uri });
        }
        entry.mtime = Date.now();
        entry.size = content.byteLength;
        entry.data = content;
        this._fireSoon({ type: vscode.FileChangeType.Changed, uri });
    }
    // --- manage files/folders
    rename(oldUri, newUri, options) {
        if (!options.overwrite && this._lookup(newUri, true)) {
            throw vscode.FileSystemError.FileExists(newUri);
        }
        const entry = this._lookup(oldUri, false);
        const oldParent = this._lookupParentDirectory(oldUri);
        const newParent = this._lookupParentDirectory(newUri);
        const newName = path.posix.basename(newUri.path);
        oldParent.entries.delete(entry.name);
        entry.name = newName;
        newParent.entries.set(newName, entry);
        this._fireSoon({ type: vscode.FileChangeType.Deleted, uri: oldUri }, { type: vscode.FileChangeType.Created, uri: newUri });
    }
    delete(uri) {
        const dirname = uri.with({ path: path.posix.dirname(uri.path) });
        const basename = path.posix.basename(uri.path);
        const parent = this._lookupAsDirectory(dirname, false);
        if (!parent.entries.has(basename)) {
            throw vscode.FileSystemError.FileNotFound(uri);
        }
        parent.entries.delete(basename);
        parent.mtime = Date.now();
        parent.size -= 1;
        this._fireSoon({ type: vscode.FileChangeType.Changed, uri: dirname }, { uri, type: vscode.FileChangeType.Deleted });
    }
    createDirectory(uri) {
        const basename = path.posix.basename(uri.path);
        const dirname = uri.with({ path: path.posix.dirname(uri.path) });
        const parent = this._lookupAsDirectory(dirname, false);
        const entry = new Directory(basename);
        parent.entries.set(entry.name, entry);
        parent.mtime = Date.now();
        parent.size += 1;
        this._fireSoon({ type: vscode.FileChangeType.Changed, uri: dirname }, { type: vscode.FileChangeType.Created, uri });
    }
    _lookup(uri, silent) {
        const parts = uri.path.split("/");
        let entry = this.root;
        for (const part of parts) {
            if (!part) {
                continue;
            }
            let child;
            if (entry instanceof Directory) {
                child = entry.entries.get(part);
            }
            if (!child) {
                if (!silent) {
                    throw vscode.FileSystemError.FileNotFound(uri);
                }
                else {
                    return undefined;
                }
            }
            entry = child;
        }
        return entry;
    }
    _lookupAsDirectory(uri, silent) {
        const entry = this._lookup(uri, silent);
        if (entry instanceof Directory) {
            return entry;
        }
        throw vscode.FileSystemError.FileNotADirectory(uri);
    }
    _lookupAsFile(uri, silent) {
        const entry = this._lookup(uri, silent);
        if (entry instanceof File) {
            return entry;
        }
        throw vscode.FileSystemError.FileIsADirectory(uri);
    }
    _lookupParentDirectory(uri) {
        const dirname = uri.with({ path: path.posix.dirname(uri.path) });
        return this._lookupAsDirectory(dirname, false);
    }
    watch(_resource) {
        return new vscode.Disposable(() => { });
    }
    _fireSoon(...events) {
        this._bufferedEvents.push(...events);
        if (this._fireSoonHandle) {
            clearTimeout(this._fireSoonHandle);
        }
        this._fireSoonHandle = setTimeout(() => {
            this._emitter.fire(this._bufferedEvents);
            this._bufferedEvents.length = 0;
        }, 5);
    }
}
exports.MemFS = MemFS;


/***/ }),
/* 6 */
/***/ ((module) => {

module.exports = require("path");

/***/ }),
/* 7 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const vscode_1 = __webpack_require__(1);
const getNonce_1 = __webpack_require__(4);
class CreateProjectProvider {
    constructor(_extensionUri) {
        this._extensionUri = _extensionUri;
    }
    resolveWebviewView(webviewView, context, _token) {
        this._view = webviewView;
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri],
        };
        webviewView.webview.html = this.getHtmlForWebview(webviewView.webview);
    }
    getHtmlForWebview(webview) {
        const styleMainUri = webview.asWebviewUri(vscode_1.Uri.joinPath(this._extensionUri, "webview", "createProject", "css", "main.538f74f5.chunk.css"));
        const script1Uri = webview.asWebviewUri(vscode_1.Uri.joinPath(this._extensionUri, "webview", "createProject", "js", "2.25c34183.chunk.js"));
        const script2Uri = webview.asWebviewUri(vscode_1.Uri.joinPath(this._extensionUri, "webview", "createProject", "js", "main.33523783.chunk.js"));
        const nonce = getNonce_1.getNonce();
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
exports.default = CreateProjectProvider;
CreateProjectProvider.viewType = "picode.editorview";


/***/ })
/******/ 	]);
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __webpack_require__(0);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;
//# sourceMappingURL=extension.js.map