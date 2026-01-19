import * as vscode from 'vscode';
import { exec } from 'child_process';
import * as path from 'path';

export function activate(context: vscode.ExtensionContext) {

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

            return new Promise<void>((resolve) => {
                const pythonCommand = `python "${scriptPath}" "${filePath}"`;

                exec(pythonCommand, (error, stdout, stderr) => {
                    
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
                        const decorations: vscode.DecorationOptions[] = [];

                        findings.forEach((finding: any) => {
                            // VS Code uses 0-based indexing, Semgrep uses 1-based
                            const startLine = finding.line - 1;
                            const endLine = finding.endLine ? finding.endLine - 1 : startLine;
                            
                            const range = new vscode.Range(startLine, 0, endLine, 1000);
                            
                            const decoration: vscode.DecorationOptions = {
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

                    } catch (e: any) {
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

export function deactivate() {}