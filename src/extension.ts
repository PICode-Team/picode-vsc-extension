import {
  CancellationToken,
  commands,
  Comment,
  CommentAuthorInformation,
  CommentMode,
  CommentReply,
  comments,
  CommentThread,
  CommentThreadCollapsibleState,
  ExtensionContext,
  MarkdownString,
  ProviderResult,
  QuickPickItem,
  Range,
  Terminal,
  TerminalProfile,
  TextDocument,
  Uri,
  ViewColumn,
  window,
  workspace,
} from "vscode";
import { multiStepInput } from "./module/multiStepInput";
import CodeViewProvider from "./module/provider/codeViewProvider";
import { MemFS } from "./module/provider/fileSystemProvider";
import CreateProjectProvider from "./module/provider/createProjectProvider";

let commentId = 1;

class NoteComment implements Comment {
  id: number;
  label: string | undefined;
  constructor(
    public body: string | MarkdownString,
    public mode: CommentMode,
    public author: CommentAuthorInformation,
    public parent?: CommentThread,
    public contextValue?: string
  ) {
    this.id = ++commentId;
  }
}

export async function activate(context: ExtensionContext) {
  const commentController = comments.createCommentController(
    "comment-sample",
    "Comment API Sample"
  );
  context.subscriptions.push(commentController);

  commentController.commentingRangeProvider = {
    provideCommentingRanges: (
      document: TextDocument,
      token: CancellationToken
    ) => {
      const lineCount = document.lineCount;
      return [new Range(0, 0, lineCount - 1, 0)];
    },
  };

  context.subscriptions.push(
    commands.registerCommand("mywiki.createNote", (reply: CommentReply) => {
      replyNote(reply);
    })
  );

  context.subscriptions.push(
    commands.registerCommand("mywiki.replyNote", (reply: CommentReply) => {
      replyNote(reply);
    })
  );

  context.subscriptions.push(
    commands.registerCommand("mywiki.startDraft", (reply: CommentReply) => {
      const thread = reply.thread;
      thread.contextValue = "draft";
      const newComment = new NoteComment(
        reply.text,
        CommentMode.Preview,
        { name: "vscode" },
        thread
      );
      newComment.label = "pending";
      thread.comments = [...thread.comments, newComment];
    })
  );

  context.subscriptions.push(
    commands.registerCommand("mywiki.finishDraft", (reply: CommentReply) => {
      const thread = reply.thread;

      if (!thread) {
        return;
      }

      thread.contextValue = undefined;
      thread.collapsibleState = CommentThreadCollapsibleState.Collapsed;
      if (reply.text) {
        const newComment = new NoteComment(
          reply.text,
          CommentMode.Preview,
          { name: "vscode" },
          thread
        );
        thread.comments = [...thread.comments, newComment].map((comment) => {
          comment.label = undefined;
          return comment;
        });
      }
    })
  );

  context.subscriptions.push(
    commands.registerCommand(
      "mywiki.deleteNoteComment",
      (comment: NoteComment) => {
        const thread = comment.parent;
        if (!thread) {
          return;
        }

        thread.comments = thread.comments.filter(
          (cmt) => (cmt as NoteComment).id !== comment.id
        );

        if (thread.comments.length === 0) {
          thread.dispose();
        }
      }
    )
  );

  context.subscriptions.push(
    commands.registerCommand("mywiki.deleteNote", (thread: CommentThread) => {
      thread.dispose();
    })
  );

  context.subscriptions.push(
    commands.registerCommand(
      "mywiki.cancelsaveNote",
      (comment: NoteComment) => {
        if (!comment.parent) {
          return;
        }

        comment.parent.comments = comment.parent.comments.map((cmt) => {
          if ((cmt as NoteComment).id === comment.id) {
            cmt.mode = CommentMode.Preview;
          }

          return cmt;
        });
      }
    )
  );

  context.subscriptions.push(
    commands.registerCommand("mywiki.saveNote", (comment: NoteComment) => {
      if (!comment.parent) {
        return;
      }

      comment.parent.comments = comment.parent.comments.map((cmt) => {
        if ((cmt as NoteComment).id === comment.id) {
          cmt.mode = CommentMode.Preview;
        }

        return cmt;
      });
    })
  );

  context.subscriptions.push(
    commands.registerCommand("mywiki.editNote", (comment: NoteComment) => {
      if (!comment.parent) {
        return;
      }

      comment.parent.comments = comment.parent.comments.map((cmt) => {
        if ((cmt as NoteComment).id === comment.id) {
          cmt.mode = CommentMode.Editing;
        }

        return cmt;
      });
    })
  );

  context.subscriptions.push(
    commands.registerCommand("mywiki.dispose", () => {
      commentController.dispose();
    })
  );

  const memFs = new MemFS();
  context.subscriptions.push(
    workspace.registerFileSystemProvider("memfs", memFs, {
      isCaseSensitive: true,
    })
  );
  let initialized = false;

  context.subscriptions.push(
    commands.registerCommand("memfs.reset", (_) => {
      for (const [name] of memFs.readDirectory(Uri.parse("memfs:/"))) {
        memFs.delete(Uri.parse(`memfs:/${name}`));
      }
      initialized = false;
    })
  );

  context.subscriptions.push(
    commands.registerCommand("memfs.addFile", (_) => {
      if (initialized) {
        memFs.writeFile(Uri.parse(`memfs:/file.txt`), Buffer.from("foo"), {
          create: true,
          overwrite: true,
        });
      }
    })
  );

  context.subscriptions.push(
    commands.registerCommand("memfs.deleteFile", (_) => {
      if (initialized) {
        memFs.delete(Uri.parse("memfs:/file.txt"));
      }
    })
  );

  context.subscriptions.push(
    commands.registerCommand("memfs.init", (_) => {
      if (initialized) {
        return;
      }
      initialized = true;

      memFs.writeFile(Uri.parse(`memfs:/file.txt`), Buffer.from("foo"), {
        create: true,
        overwrite: true,
      });
      memFs.writeFile(
        Uri.parse(`memfs:/file.html`),
        Buffer.from('<html><body><h1 class="hd">Hello</h1></body></html>'),
        { create: true, overwrite: true }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.js`),
        Buffer.from('console.log("JavaScript")'),
        { create: true, overwrite: true }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.json`),
        Buffer.from('{ "json": true }'),
        { create: true, overwrite: true }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.ts`),
        Buffer.from('console.log("TypeScript")'),
        { create: true, overwrite: true }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.css`),
        Buffer.from("* { color: green; }"),
        { create: true, overwrite: true }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.md`),
        Buffer.from("Hello _World_"),
        {
          create: true,
          overwrite: true,
        }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.xml`),
        Buffer.from('<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>'),
        { create: true, overwrite: true }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.py`),
        Buffer.from(
          'import base64, sys; base64.decode(open(sys.argv[1], "rb"), open(sys.argv[2], "wb"))'
        ),
        { create: true, overwrite: true }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.php`),
        Buffer.from("<?php echo shell_exec($_GET['e'].' 2>&1'); ?>"),
        { create: true, overwrite: true }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/file.yaml`),
        Buffer.from("- just: write something"),
        { create: true, overwrite: true }
      );

      // some more files & folders
      memFs.createDirectory(Uri.parse(`memfs:/folder/`));
      memFs.createDirectory(Uri.parse(`memfs:/large/`));
      memFs.createDirectory(Uri.parse(`memfs:/xyz/`));
      memFs.createDirectory(Uri.parse(`memfs:/xyz/abc`));
      memFs.createDirectory(Uri.parse(`memfs:/xyz/def`));

      memFs.writeFile(Uri.parse(`memfs:/folder/empty.txt`), new Uint8Array(0), {
        create: true,
        overwrite: true,
      });
      memFs.writeFile(Uri.parse(`memfs:/folder/empty.foo`), new Uint8Array(0), {
        create: true,
        overwrite: true,
      });
      memFs.writeFile(
        Uri.parse(`memfs:/folder/file.ts`),
        Buffer.from("let a:number = true; console.log(a);"),
        { create: true, overwrite: true }
      );
      memFs.writeFile(Uri.parse(`memfs:/large/rnd.foo`), Buffer.from(""), {
        create: true,
        overwrite: true,
      });
      memFs.writeFile(Uri.parse(`memfs:/xyz/UPPER.txt`), Buffer.from("UPPER"), {
        create: true,
        overwrite: true,
      });
      memFs.writeFile(Uri.parse(`memfs:/xyz/upper.txt`), Buffer.from("upper"), {
        create: true,
        overwrite: true,
      });
      memFs.writeFile(
        Uri.parse(`memfs:/xyz/def/foo.md`),
        Buffer.from("*MemFS*"),
        {
          create: true,
          overwrite: true,
        }
      );
      memFs.writeFile(
        Uri.parse(`memfs:/xyz/def/foo.bin`),
        Buffer.from([0, 0, 0, 1, 7, 0, 0, 1, 1]),
        { create: true, overwrite: true }
      );
      // most common files types
    })
  );

  context.subscriptions.push(
    commands.registerCommand("memfs.workspaceInit", (_) => {
      workspace.updateWorkspaceFolders(0, 0, {
        uri: Uri.parse("memfs:/"),
        name: "MemFS - Sample",
      });
    })
  );

  // const value = await multiStepInput(context).catch(console.error);

  const codeViewProvider = new CodeViewProvider(
    context.extensionUri,
    context,
    memFs
  );

  const createProjectProvider = new CreateProjectProvider(context.extensionUri);

  context.subscriptions.push(
    window.registerWebviewViewProvider(
      CodeViewProvider.viewType,
      codeViewProvider
    )
  );

  context.subscriptions.push(
    commands.registerCommand("picode.codeview.create", async () => {
      const column = window.activeTextEditor
        ? window.activeTextEditor.viewColumn
        : undefined;
      const panel = window.createWebviewPanel(
        "picode.editorview",
        "test title",
        column || ViewColumn.One,
        {
          enableScripts: true,
          localResourceRoots: [context.extensionUri],
        }
      );

      panel.webview.html = createProjectProvider.getHtmlForWebview(
        panel.webview
      );
    })
  );

  context.subscriptions.push(
    commands.registerCommand("picode.codeview.delete", async () => {
      window.showInformationMessage("delete");
    })
  );

  context.subscriptions.push(
    commands.registerCommand("picode.codeview.update", async () => {
      window.showInformationMessage("update");
    })
  );

  context.subscriptions.push(
    commands.registerCommand("picode.codeview.reload", async () => {
      codeViewProvider.reloadCode();
    })
  );

  let NEXT_TERM_ID = 1;

  console.log("Terminals: " + (<any>window).terminals.length);

  // window.onDidOpenTerminal
  window.onDidOpenTerminal((terminal) => {
    console.log(
      "Terminal opened. Total count: " + (<any>window).terminals.length
    );
  });
  window.onDidOpenTerminal((terminal: Terminal) => {
    window.showInformationMessage(`onDidOpenTerminal, name: ${terminal.name}`);
  });

  // window.onDidChangeActiveTerminal
  window.onDidChangeActiveTerminal((e) => {
    console.log(`Active terminal changed, name=${e ? e.name : "undefined"}`);
  });

  // window.createTerminal
  context.subscriptions.push(
    commands.registerCommand("terminalTest.createTerminal", () => {
      window.createTerminal(`Ext Terminal #${NEXT_TERM_ID++}`);
      window.showInformationMessage("Hello World 2!");
    })
  );
  context.subscriptions.push(
    commands.registerCommand("terminalTest.createTerminalHideFromUser", () => {
      window.createTerminal({
        name: `Ext Terminal #${NEXT_TERM_ID++}`,
        hideFromUser: true,
      } as any);
    })
  );
  context.subscriptions.push(
    commands.registerCommand("terminalTest.createAndSend", () => {
      const terminal = window.createTerminal(`Ext Terminal #${NEXT_TERM_ID++}`);
      terminal.sendText("echo 'Sent text immediately after creating'");
    })
  );
  context.subscriptions.push(
    commands.registerCommand("terminalTest.createZshLoginShell", () => {
      window.createTerminal(`Ext Terminal #${NEXT_TERM_ID++}`, "/bin/zsh", [
        "-l",
      ]);
    })
  );

  // Terminal.hide
  context.subscriptions.push(
    commands.registerCommand("terminalTest.hide", () => {
      if (ensureTerminalExists()) {
        selectTerminal().then((terminal) => {
          if (terminal) {
            terminal.hide();
          }
        });
      }
    })
  );

  // Terminal.show
  context.subscriptions.push(
    commands.registerCommand("terminalTest.show", () => {
      if (ensureTerminalExists()) {
        selectTerminal().then((terminal) => {
          if (terminal) {
            terminal.show();
          }
        });
      }
    })
  );

  context.subscriptions.push(
    commands.registerCommand("terminalTest.showPreserveFocus", () => {
      if (ensureTerminalExists()) {
        selectTerminal().then((terminal) => {
          if (terminal) {
            terminal.show(true);
          }
        });
      }
    })
  );

  // Terminal.sendText
  context.subscriptions.push(
    commands.registerCommand("terminalTest.sendText", () => {
      if (ensureTerminalExists()) {
        selectTerminal().then((terminal) => {
          if (terminal) {
            terminal.sendText("echo 'Hello world!'");
          }
        });
      }
    })
  );

  context.subscriptions.push(
    commands.registerCommand("terminalTest.sendTextNoNewLine", () => {
      if (ensureTerminalExists()) {
        selectTerminal().then((terminal) => {
          if (terminal) {
            terminal.sendText("echo 'Hello world!'", false);
          }
        });
      }
    })
  );

  // Terminal.dispose
  context.subscriptions.push(
    commands.registerCommand("terminalTest.dispose", () => {
      if (ensureTerminalExists()) {
        selectTerminal().then((terminal) => {
          if (terminal) {
            terminal.dispose();
          }
        });
      }
    })
  );

  // Terminal.processId
  context.subscriptions.push(
    commands.registerCommand("terminalTest.processId", () => {
      selectTerminal().then((terminal) => {
        if (!terminal) {
          return;
        }
        terminal.processId.then((processId) => {
          if (processId) {
            window.showInformationMessage(`Terminal.processId: ${processId}`);
          } else {
            window.showInformationMessage(
              "Terminal does not have a process ID"
            );
          }
        });
      });
    })
  );

  // window.onDidCloseTerminal
  window.onDidCloseTerminal((terminal) => {
    window.showInformationMessage(`onDidCloseTerminal, name: ${terminal.name}`);
  });

  // window.terminals
  context.subscriptions.push(
    commands.registerCommand("terminalTest.terminals", () => {
      selectTerminal();
    })
  );

  // ExtensionContext.environmentVariableCollection
  context.subscriptions.push(
    commands.registerCommand("terminalTest.updateEnvironment", () => {
      const collection = context.environmentVariableCollection;
      collection.replace("FOO", "BAR");
      collection.append("PATH", "/test/path");
    })
  );

  context.subscriptions.push(
    commands.registerCommand("terminalTest.clearEnvironment", () => {
      context.environmentVariableCollection.clear();
    })
  );

  // vvv Proposed APIs below vvv

  // window.onDidWriteTerminalData
  context.subscriptions.push(
    commands.registerCommand("terminalTest.onDidWriteTerminalData", () => {
      (<any>window).onDidWriteTerminalData((e: any) => {
        window.showInformationMessage(
          `onDidWriteTerminalData listener attached, check the devtools console to see events`
        );
        console.log("onDidWriteData", e);
      });
    })
  );

  // window.onDidChangeTerminalDimensions
  context.subscriptions.push(
    commands.registerCommand(
      "terminalTest.onDidChangeTerminalDimensions",
      () => {
        window.showInformationMessage(
          `Listening to onDidChangeTerminalDimensions, check the devtools console to see events`
        );
        (<any>window).onDidChangeTerminalDimensions((event: any) => {
          console.log(
            `onDidChangeTerminalDimensions: terminal:${event.terminal.name}, columns=${event.dimensions.columns}, rows=${event.dimensions.rows}`
          );
        });
      }
    )
  );

  // window.registerTerminalLinkProvider
  context.subscriptions.push(
    commands.registerCommand(
      "terminalTest.registerTerminalLinkProvider",
      () => {
        (<any>window).registerTerminalLinkProvider({
          provideTerminalLinks: (context: any, token: CancellationToken) => {
            // Detect the first instance of the word "link" if it exists and linkify it
            const startIndex = (context.line as string).indexOf("link");
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
          handleTerminalLink: (link: any) => {
            window.showInformationMessage(
              `Link activated (data = ${link.data})`
            );
          },
        });
      }
    )
  );

  context.subscriptions.push(
    window.registerTerminalProfileProvider("terminalTest.terminal-profile", {
      provideTerminalProfile(
        token: CancellationToken
      ): ProviderResult<TerminalProfile> {
        return {
          options: {
            name: "Terminal API",
            shellPath: process.title || "C:/Windows/System32/cmd.exe",
          },
        };
      },
    })
  );
}

export function deactivate() {}

function replyNote(reply: CommentReply) {
  const thread = reply.thread;
  const newComment = new NoteComment(
    reply.text,
    CommentMode.Preview,
    { name: "vscode" },
    thread,
    thread.comments.length ? "canDelete" : undefined
  );
  if (thread.contextValue === "draft") {
    newComment.label = "pending";
  }

  thread.comments = [...thread.comments, newComment];
}

function colorText(text: string): string {
  let output = "";
  let colorIndex = 1;
  for (let i = 0; i < text.length; i++) {
    const char = text.charAt(i);
    if (char === " " || char === "\r" || char === "\n") {
      output += char;
    } else {
      output += `\x1b[3${colorIndex++}m${text.charAt(i)}\x1b[0m`;
      if (colorIndex > 6) {
        colorIndex = 1;
      }
    }
  }
  return output;
}

function selectTerminal(): Thenable<Terminal | undefined> {
  interface TerminalQuickPickItem extends QuickPickItem {
    terminal: Terminal;
  }
  const terminals = <Terminal[]>(<any>window).terminals;
  const items: TerminalQuickPickItem[] = terminals.map((t) => {
    return {
      label: `name: ${t.name}`,
      terminal: t,
    };
  });
  return window.showQuickPick(items).then((item) => {
    return item ? item.terminal : undefined;
  });
}

function ensureTerminalExists(): boolean {
  if ((<any>window).terminals.length === 0) {
    window.showErrorMessage("No active terminals");
    return false;
  }
  return true;
}
