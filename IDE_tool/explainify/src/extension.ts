import * as vscode from 'vscode';
import { exec } from 'child_process';
import * as path from 'path';

let globalFindings: any[] = [];

// Helper function for marking the vulnerable files with a '!' and making the file names yellow
class VulnerabilityDecorationProvider implements vscode.FileDecorationProvider {
    
    private _onDidChange = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
    readonly onDidChangeFileDecorations = this._onDidChange.event;

    refresh() {
        this._onDidChange.fire(undefined);
    }

    provideFileDecoration(uri: vscode.Uri): vscode.FileDecoration | undefined {
        if (globalFindings.length === 0) return undefined;

        const fsPath = uri.fsPath;

        const hasIssues = globalFindings.some(finding => {
            const fPath = finding.file_path || finding.path;
            if (!fPath) return false;

            if (path.isAbsolute(fPath)) {
                return fPath === fsPath;
            } 
            if (vscode.workspace.workspaceFolders) {
                const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
                return path.join(root, fPath) === fsPath;
            }
            return false;
        });

        if (hasIssues) {
            return {
                badge: '!',
                color: new vscode.ThemeColor('editorWarning.foreground'),
                tooltip: 'Vulnerabilities detected by Explainify'
            };
        }

        return undefined;
    }
}


export function activate(context: vscode.ExtensionContext) {

    const outputChannel = vscode.window.createOutputChannel("Explainify Analyzer");
    const diagnosticCollection = vscode.languages.createDiagnosticCollection("explainify");
    context.subscriptions.push(diagnosticCollection);

    const decorationProvider = new VulnerabilityDecorationProvider();
    context.subscriptions.push(vscode.window.registerFileDecorationProvider(decorationProvider));

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

    let disposable = vscode.commands.registerCommand('explainify.analyzeWorkspace', () => {
        
        if (!vscode.workspace.workspaceFolders) {
            vscode.window.showErrorMessage('No project folder is open!');
            return;
        }
        const workspaceRoot = vscode.workspace.workspaceFolders[0].uri.fsPath;
        const scriptPath = path.join(context.extensionPath, 'scripts', 'analyze.py');

        outputChannel.clear();
        outputChannel.show(true);
        outputChannel.appendLine(`Starting analysis on: ${workspaceRoot}`);

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Scanning project for vulnerabilities...",
            cancellable: false
        }, async () => {
            
            return new Promise<void>((resolve) => {
                const pythonCommand = `python "${scriptPath}" "${workspaceRoot}"`;

                exec(pythonCommand, (error, stdout, stderr) => {
                    if (stderr) outputChannel.appendLine(`[Log]: ${stderr}`);

                    if (error && !stdout) {
                        vscode.window.showErrorMessage("Analysis failed. Check Output panel.");
                        outputChannel.appendLine(`Execution Error: ${error.message}`);
                        resolve(); return;
                    }

                    try {
                        // The following code parses the JSON output with the explanations 
                        let findings: any[] = [];
                        let parsedSuccess = false;
                        let scanPos = 0;

                        while (scanPos < stdout.length) {
                            const firstOpen = stdout.indexOf('[', scanPos);
                            const firstBrace = stdout.indexOf('{', scanPos);
                            
                            let currentStart = -1;
                            if (firstOpen !== -1 && firstBrace !== -1) {
                                currentStart = Math.min(firstOpen, firstBrace);
                            } else if (firstOpen !== -1) {
                                currentStart = firstOpen;
                            } else if (firstBrace !== -1) {
                                currentStart = firstBrace;
                            }

                            if (currentStart === -1) break; 

                            const lastClose = stdout.search(/[\]\}][^\]\}]*$/);
                            
                            if (lastClose !== -1 && lastClose > currentStart) {
                                const potentialJson = stdout.substring(currentStart, lastClose + 1);
                                try {
                                    const rawFindings = JSON.parse(potentialJson);
                                    
                                    if (Array.isArray(rawFindings)) {
                                        findings = rawFindings;
                                    } else if (typeof rawFindings === 'object' && rawFindings !== null) {
                                        Object.entries(rawFindings).forEach(([filePathKey, issuesList]) => {
                                            if (Array.isArray(issuesList)) {
                                                const issuesWithPaths = issuesList.map((issue: any) => ({
                                                    ...issue,
                                                    file_path: filePathKey
                                                }));
                                                findings = findings.concat(issuesWithPaths);
                                            }
                                        });
                                    }
                                    
                                    if (findings.length > 0) {
                                        parsedSuccess = true;
                                        break;
                                    }
                                    parsedSuccess = true; 
                                } catch (e) { }
                            }
                            scanPos = currentStart + 1;
                        }

                        if (!parsedSuccess && stdout.trim().length > 0) {
                            throw new Error("Could not parse any valid JSON from output.");
                        }

                        globalFindings = findings;

                        decorationProvider.refresh();

                        if (findings.length === 0) {
                            vscode.window.showInformationMessage("Project is clean.");
                            diagnosticCollection.clear();
                            updateDecorations(vscode.window.activeTextEditor);
                            resolve();
                            return;
                        }

                        diagnosticCollection.clear(); 
                        const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

                        findings.forEach((finding) => {
                            let filePath = finding.file_path || finding.path;
                            if (!filePath) return;

                            let absolutePath = filePath;
                            if (!path.isAbsolute(filePath)) {
                                absolutePath = path.join(workspaceRoot, filePath);
                            }

                            const fileUri = vscode.Uri.file(absolutePath);
                            const uriStr = fileUri.toString();
                            
                            const startLine = (finding.line || 1) - 1;
                            const endLine = (finding.endLine || startLine + 1) - 1;
                            const range = new vscode.Range(startLine, 0, endLine, 1000);
                        });

                        diagnosticMap.forEach((diags, uriStr) => {
                            diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
                        });

                        if (vscode.window.activeTextEditor) {
                            updateDecorations(vscode.window.activeTextEditor);
                        }

                        vscode.window.showInformationMessage(`Found ${findings.length} issues.`);
                        outputChannel.appendLine(`Analysis Complete.`);

                    } catch (e: any) {
                        outputChannel.appendLine(`Error: ${e.message}`);
                        outputChannel.appendLine(`Output: "${stdout}"`);
                    }
                    resolve();
                });
            });
        });
    });

    vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor) {
            updateDecorations(editor);
        }
    }, null, context.subscriptions);

    function updateDecorations(editor: vscode.TextEditor | undefined) {
        if (!editor) return;

        const currentFilePath = editor.document.uri.fsPath;
        const decorations: vscode.DecorationOptions[] = [];

        const fileFindings = globalFindings.filter(f => {
            const fPath = f.file_path || f.path;
            if (path.isAbsolute(fPath)) {
                return fPath === currentFilePath;
            } else {
                if (vscode.workspace.workspaceFolders) {
                    const abs = path.join(vscode.workspace.workspaceFolders[0].uri.fsPath, fPath);
                    return abs === currentFilePath;
                }
                return false;
            }
        });

        fileFindings.forEach(finding => {
            const startLine = (finding.line || 1) - 1;
            const endLine = (finding.endLine || startLine + 1) - 1;
            const range = new vscode.Range(startLine, 0, endLine, 1000);
            const message = finding.vulnerability ? String(finding.vulnerability) : "Security Vulnerability";

            decorations.push({
                range: range,
                renderOptions: { after: { contentText: ` [${message}]` } },
                hoverMessage: new vscode.MarkdownString(`### AI Explanation:\n${finding.ai_explanation}`)
            });
        });

        editor.setDecorations(vulnerabilityDecorationType, decorations);
    }

    context.subscriptions.push(disposable);
}

export function deactivate() {}