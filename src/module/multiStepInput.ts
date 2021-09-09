import {
  window,
  Disposable,
  QuickInputButton,
  QuickInput,
  ExtensionContext,
  QuickInputButtons,
} from "vscode";

export async function multiStepInput(context: ExtensionContext) {
  interface State {
    title: string;
    step: number;
    totalSteps: number;
    port: string;
    id: string;
    password: string;
  }

  async function collectInputs() {
    const state = {} as Partial<State>;
    await MultiStepInput.run((input) => inputPort(input, state));
    return state as State;
  }

  const title = "Connect PICode SSH";

  async function inputPort(input: MultiStepInput, state: Partial<State>) {
    state.port = await input.showInputBox({
      title,
      step: 1,
      totalSteps: 3,
      value: state.port || "",
      prompt: "Enter your PICode domain",
      validate: validatePortIsNumber,
      shouldResume: shouldResume,
    });
    return (input: MultiStepInput) => inputName(input, state);
  }

  async function inputName(input: MultiStepInput, state: Partial<State>) {
    state.id = await input.showInputBox({
      title,
      step: 2,
      totalSteps: 3,
      value: state.id || "",
      prompt: "Enter your ID",
      validate: validateNameIsUnique,
      shouldResume: shouldResume,
    });
    return (input: MultiStepInput) => inputPassword(input, state);
  }

  async function inputPassword(input: MultiStepInput, state: Partial<State>) {
    state.password = await input.showInputBox({
      title,
      step: 3,
      totalSteps: 3,
      value: state.password || "",
      prompt: "Enter your password",
      validate: validatePassword,
      shouldResume: shouldResume,
    });
  }

  function shouldResume() {
    return new Promise<boolean>((resolve, reject) => {});
  }

  async function validatePortIsNumber(port: string) {
    return false ? "" : "";
  }

  async function validateNameIsUnique(name: string) {
    return name === "vscode" ? "Name not unique" : undefined;
  }

  async function validatePassword(name: string) {
    return name === "vscode" ? "Name not unique" : undefined;
  }

  const state = await collectInputs();

  return state;
}

class InputFlowAction {
  static back = new InputFlowAction();
  static cancel = new InputFlowAction();
  static resume = new InputFlowAction();
}

type InputStep = (input: MultiStepInput) => Thenable<InputStep | void>;

interface InputBoxParameters {
  title: string;
  step: number;
  totalSteps: number;
  value: string;
  prompt: string;
  validate: (value: string) => Promise<string | undefined>;
  buttons?: QuickInputButton[];
  shouldResume: () => Thenable<boolean>;
}

class MultiStepInput {
  static async run<T>(start: InputStep) {
    const input = new MultiStepInput();
    return input.stepThrough(start);
  }

  private current?: QuickInput;
  private steps: InputStep[] = [];

  private async stepThrough<T>(start: InputStep) {
    let step: InputStep | void = start;
    while (step) {
      this.steps.push(step);
      if (this.current) {
        this.current.enabled = false;
        this.current.busy = true;
      }
      try {
        step = await step(this);
      } catch (err) {
        if (err === InputFlowAction.back) {
          this.steps.pop();
          step = this.steps.pop();
        } else if (err === InputFlowAction.resume) {
          step = this.steps.pop();
        } else if (err === InputFlowAction.cancel) {
          step = undefined;
        } else {
          throw err;
        }
      }
    }
    if (this.current) {
      this.current.dispose();
    }
  }

  async showInputBox<P extends InputBoxParameters>({
    title,
    step,
    totalSteps,
    value,
    prompt,
    validate,
    buttons,
    shouldResume,
  }: P) {
    const disposables: Disposable[] = [];
    try {
      return await new Promise<
        string | (P extends { buttons: (infer I)[] } ? I : never)
      >((resolve, reject) => {
        const input = window.createInputBox();
        input.title = title;
        input.step = step;
        input.totalSteps = totalSteps;
        input.value = value || "";
        input.prompt = prompt;
        input.buttons = [
          ...(this.steps.length > 1 ? [QuickInputButtons.Back] : []),
          ...(buttons || []),
        ];
        let validating = validate("");
        disposables.push(
          input.onDidTriggerButton((item) => {
            if (item === QuickInputButtons.Back) {
              reject(InputFlowAction.back);
            } else {
              resolve(<any>item);
            }
          }),
          input.onDidAccept(async () => {
            const value = input.value;
            input.enabled = false;
            input.busy = true;
            if (!(await validate(value))) {
              resolve(value);
            }
            input.enabled = true;
            input.busy = false;
          }),
          input.onDidChangeValue(async (text) => {
            const current = validate(text);
            validating = current;
            const validationMessage = await current;
            if (current === validating) {
              input.validationMessage = validationMessage;
            }
          }),
          input.onDidHide(() => {
            (async () => {
              reject(
                shouldResume && (await shouldResume())
                  ? InputFlowAction.resume
                  : InputFlowAction.cancel
              );
            })().catch(reject);
          })
        );
        if (this.current) {
          this.current.dispose();
        }
        this.current = input;
        this.current.show();
      });
    } finally {
      disposables.forEach((d) => d.dispose());
    }
  }
}
