import * as vscode from 'vscode';
import { exec } from 'child_process';
import * as path from 'path';

export function activate(context: vscode.ExtensionContext) {

    console.log('Semgrep-Mistral Extension is now active!');
    const outputChannel = vscode.window.createOutputChannel("Semgrep AI Analyzer");
    const vulnerabilityDecorationType = vscode.window.createTextEditorDecorationType({
        textDecoration: 'underline wavy yellow', 
        overviewRulerColor: 'yellow',
        overviewRulerLane: vscode.OverviewRulerLane.Right,
        after: {
            margin: '0 0 0 1em',
            textDecoration: 'none',
            fontWeight: 'bold',
            color: '#ffff00' 
        }
    });

    let disposable = vscode.commands.registerCommand('semgrep-mistral-analyser.analyzeFile', () => {
        
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No file is currently open.');
            return;
        }

        const filePath = editor.document.fileName;
        const scriptPath = path.join(context.extensionPath, 'scripts', 'analyze.py');
        outputChannel.clear();
        outputChannel.appendLine(`Starting analysis on: ${filePath}`);

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Running Semgrep & AI Analysis...",
            cancellable: false
        }, async (progress) => {
            
            await editor.document.save();

            return new Promise<void>((resolve) => {
                const pythonCommand = `python "${scriptPath}" "${filePath}"`;

                exec(pythonCommand, (error, stdout, stderr) => {
                    
                    if (stderr) outputChannel.appendLine(`[Python Log]: ${stderr}`);

                    if (error) {
                        const errorMsg = `Analysis execution failed: ${error.message}`;
                        vscode.window.showErrorMessage("Analysis failed. Check Output panel.");
                        outputChannel.appendLine(`${errorMsg}`);
                        outputChannel.show(true); 
                        resolve();
                        return;
                    }

                    try {
                        const firstOpen = stdout.search(/[\[\{]/); 
                        const lastClose = stdout.search(/[\]\}][^\]\}]*$/); 

                        if (firstOpen === -1 || lastClose === -1) {
                            if (stdout.trim() === "[]" || stdout.trim() === "{}") {
                            } else {
                                throw new Error("No valid JSON brackets found in output.");
                            }
                        }

                        let findings: any[] = [];
                        
                        if (firstOpen !== -1 && lastClose !== -1) {
                            const cleanJson = stdout.substring(firstOpen, lastClose + 1);
                            outputChannel.appendLine("Valid JSON structure detected. Parsing...");
                            const parsedData = JSON.parse(cleanJson);

                            if (Array.isArray(parsedData)) {
                                findings = parsedData;
                            } else if (typeof parsedData === 'object' && parsedData !== null) {
                                outputChannel.appendLine("Detected Dictionary format. Flattening...");
                                Object.values(parsedData).forEach((val: any) => {
                                    if (Array.isArray(val)) {
                                        findings = findings.concat(val);
                                    }
                                });
                            }
                        }

                        outputChannel.clear();
                        if (findings.length === 0) {
                            outputChannel.appendLine("Analysis Complete: No issues found.");
                            vscode.window.showInformationMessage("No vulnerabilities found!");
                            editor.setDecorations(vulnerabilityDecorationType, []);
                            outputChannel.show(true);
                            resolve();
                            return;
                        }

                        // // Print Findings to Output Panel
                        // findings.forEach((finding: any, index: number) => {
                        //     const line = finding.line || finding.start_line || "Unknown";
                        //     const rule = finding.message || "Unknown Rule";
                        //     const explanation = finding.ai_explanation || "No AI explanation available.";
                            
                        //     outputChannel.appendLine(`🔴 Issue #${index + 1} at Line ${line}:`);
                        //     outputChannel.appendLine(`   Rule: ${rule}`);
                        //     outputChannel.appendLine(`   ---------------------------------------------------`);
                        //     outputChannel.appendLine(`   🤖 AI Fix:`);
                        //     outputChannel.appendLine(`   ${explanation.replace(/\n/g, '\n   ')}`); 
                        //     outputChannel.appendLine("===================================================\n");
                        // });

                        // outputChannel.show(true);
                        const decorations: vscode.DecorationOptions[] = [];

                        findings.forEach((finding: any) => {
                            const rawLine = finding.line || finding.start_line || 1;
                            const startLine = Math.max(0, rawLine - 1); 
                            const rawEndLine = finding.endLine || finding.end_line || rawLine;
                            const endLine = Math.max(startLine, rawEndLine - 1);

                            const range = new vscode.Range(startLine, 0, endLine, 1000);
                            
                            const message = finding.message || "Potential Issue";
                            const explanation = finding.ai_explanation || "No explanation provided.";
							const vulnerability = finding.vulnerability;

                            const decoration: vscode.DecorationOptions = {
                                range: range,
                                renderOptions: {
                                    after: {
                                        contentText: ` [${vulnerability}]` 
                                    }
                                },
                                hoverMessage: new vscode.MarkdownString(`
### AI Explanation:
${explanation}
                                `)
                            };
                            decorations.push(decoration);
                        });

                        editor.setDecorations(vulnerabilityDecorationType, decorations);
                        vscode.window.showInformationMessage(`Found ${findings.length} issues.`);

                    } catch (e: any) {
                        const failMsg = "Failed to parse analysis results. Check Output panel.";
                        vscode.window.showErrorMessage(failMsg);
                        outputChannel.show(true);
                        outputChannel.appendLine(`Parse Error: ${e.message}`);
                        outputChannel.appendLine(`Raw Output causing error:\n"${stdout}"`);
                    }
                    resolve();
                });
            });
        });
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}