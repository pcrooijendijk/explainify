"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
function activate(context) {
    console.log('Semgrep-Mistral Extension is now active!');
    // 1. Create a persistent Output Channel (Logs appear in the "Output" tab at the bottom)
    const outputChannel = vscode.window.createOutputChannel("Semgrep AI Analyzer");
    // 2. Define Visual Style (Red wavy underline + text)
    const vulnerabilityDecorationType = vscode.window.createTextEditorDecorationType({
        textDecoration: 'underline wavy red',
        overviewRulerColor: 'red',
        overviewRulerLane: vscode.OverviewRulerLane.Right,
        after: {
            margin: '0 0 0 1em',
            textDecoration: 'none',
            fontWeight: 'bold',
            color: '#ffff00'
        }
    });
    // 3. Register the Command
    let disposable = vscode.commands.registerCommand('semgrep-mistral-analyser.analyzeFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No file is currently open.');
            return;
        }
        const filePath = editor.document.fileName;
        // Path to your python script inside the extension
        const scriptPath = path.join(context.extensionPath, 'scripts', 'analyze.py');
        // Clear logs and show that we started
        outputChannel.clear();
        outputChannel.appendLine(`Starting analysis on: ${filePath}`);
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Running Vulnerability Analysis...",
            cancellable: false
        }, async (progress) => {
            await editor.document.save();
            return new Promise((resolve) => {
                const pythonCommand = `python "${scriptPath}" "${filePath}"`;
                (0, child_process_1.exec)(pythonCommand, (error, stdout, stderr) => {
                    // Log any stderr (debug info) to the output panel
                    if (stderr) {
                        outputChannel.appendLine(`[Python Log]: ${stderr}`);
                    }
                    // If error exists but no stdout, it's a critical failure
                    if (error && !stdout) {
                        const errorMsg = `Analysis execution failed: ${error.message}`;
                        vscode.window.showErrorMessage(errorMsg);
                        outputChannel.appendLine(`${errorMsg}`);
                        resolve();
                        return;
                    }
                    try {
                        // --- SMART JSON PARSING START ---
                        // We ignore everything before the first '[' and after the last ']'
                        // This filters out "ApplicationInsights" or other noisy logs
                        const firstBracket = stdout.indexOf('[');
                        const lastBracket = stdout.lastIndexOf(']');
                        if (firstBracket === -1 || lastBracket === -1) {
                            throw new Error("No valid JSON array found in Python output.");
                        }
                        const cleanJson = stdout.substring(firstBracket, lastBracket + 1);
                        outputChannel.appendLine("Valid JSON detected. Parsing...");
                        const findings = JSON.parse(cleanJson);
                        // --- SMART JSON PARSING END ---
                        if (findings.length === 0) {
                            vscode.window.showInformationMessage("No vulnerabilities found!");
                            editor.setDecorations(vulnerabilityDecorationType, []);
                            resolve();
                            return;
                        }
                        // Create decorations (highlights)
                        const decorations = [];
                        findings.forEach((finding) => {
                            // VS Code uses 0-based indexing, Semgrep uses 1-based
                            const startLine = finding.line - 1;
                            const endLine = finding.endLine ? finding.endLine - 1 : startLine;
                            const range = new vscode.Range(startLine, 0, endLine, 1000);
                            const decoration = {
                                range: range,
                                renderOptions: {
                                    after: {
                                        contentText: ` [${finding.vulnerability}]`
                                    }
                                },
                                // The tooltip when hovering over the red line
                                hoverMessage: new vscode.MarkdownString(`
### AI Explanation:
${finding.ai_explanation}
                                `)
                            };
                            decorations.push(decoration);
                        });
                        editor.setDecorations(vulnerabilityDecorationType, decorations);
                        const successMsg = `Found ${findings.length} issues.`;
                        vscode.window.showInformationMessage(successMsg);
                        outputChannel.appendLine(`${successMsg}`);
                    }
                    catch (e) {
                        const failMsg = "Failed to parse analysis results. Check Output panel.";
                        vscode.window.showErrorMessage(failMsg);
                        outputChannel.appendLine(`Parse Error: ${e.message}`);
                        outputChannel.appendLine(`Raw Output causing error:\n${stdout}`);
                    }
                    resolve();
                });
            });
        });
    });
    context.subscriptions.push(disposable);
}
function deactivate() { }
//# sourceMappingURL=extension.js.map