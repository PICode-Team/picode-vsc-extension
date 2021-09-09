(function () {
  const vscode = acquireVsCodeApi();
  const ws = initWebSocket();
  
  reloadCode();

  window.addEventListener("message", (event) => {
    const message = event.data;

    switch (message.type) {
      case "reloadCode": {
        reloadCode();
        break;
      }
      case "loadProject": {
        loadProject(message.codeName);

        getCode("test", "/test.js");
        break;
      }
      case "getCode": {
        vscode.postMessage({ type: "getCode", data: message });
        getCode(message.projectName, message.filePath);
        break;
      }
      default: {
      }
    }
  });

  function reloadCode() {
    const target = document.getElementById("root");
        target.textContent = "";
        const childList = [{projectName:"TESTWORKSPACE"}, {projectName:"TESTWORKSPACE2"}, {projectName:"TESTWORKSPACE3"}].map((v) => {
          const newRow = document.createElement("div");
          newRow.classList.add("child");

          const icon = document.createElement("div");
          icon.classList.add("icon");

          const i = document.createElement("i");
          i.classList.add("codicon");
          i.classList.add("codicon-vm");

          icon.appendChild(i);

          const text = document.createElement("div");
          text.textContent = v.projectName;

          newRow.appendChild(icon);
          newRow.appendChild(text);

          newRow.addEventListener("click", () => {
            handleCodeClick(v.projectName);
          });
          return newRow;
        });

        childList.forEach((element) => {
          target.appendChild(element);
        });
  }

  function loadProject(codeName) {
    ws.send(
      JSON.stringify({
        category: "code",
        type: "loadProject",
        data: {
          projectName: codeName,
        },
      })
    );
  }

  function getCode(projectName, filePath) {
    ws.send(
      JSON.stringify({
        category: "code",
        type: "getCode",
        data: {
          projectName: projectName,
          filePath: filePath,
        },
      })
    );
  }

  function initWebSocket() {
    const ws = new WebSocket(`ws://localhost:8000/?userId=test`);
    ws.onopen = () => {
      ws.send(JSON.stringify({ category: "connect" }));
    };

    ws.onmessage = (msg) => {
      const message = JSON.parse(msg.data);
      if (message.category === "code") {
        switch (message.type) {
          case "loadProject":
            vscode.postMessage({ type: "loadProject", root: message.data });
            break;
          case "moveFileOrDir":
          case "createDir":
          case "createFile":
          case "deleteFileOrDir":
            break;
          case "getCode":
            vscode.postMessage({ type: "getCode", data: message.data });
            break;
        }
      }
    };

    return ws;
  }

  function handleCodeClick(codeName) {
    vscode.postMessage({ type: "selectCode", codeName: codeName });
  }
})();
