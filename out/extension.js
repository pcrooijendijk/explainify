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
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
function activate(context) {
    const vulnerableLineDecoration = vscode.window.createTextEditorDecorationType({
        textDecoration: 'underline wavy #8400ff',
        overviewRulerColor: '#8400ff',
    });
    const disposable = vscode.commands.registerCommand('cweExplorer.open', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('Open a workspace folder.');
            return;
        }
        const defaultFolder = workspaceFolders[0].uri.fsPath;
        const dirUri = await vscode.window.showInputBox({ prompt: 'Path to results directory', value: 'results' });
        if (!dirUri) {
            return;
        }
        ;
        const resultsPath = path.isAbsolute(dirUri) ? dirUri : path.join(defaultFolder, dirUri);
        if (!fs.existsSync(resultsPath)) {
            vscode.window.showErrorMessage(`Results directory not found: ${resultsPath}`);
            return;
        }
        // Load explanations.json for getting the generated explanations
        const explanationsFile = path.join(resultsPath, 'explanations.json');
        let explanations = {};
        if (fs.existsSync(explanationsFile)) {
            explanations = JSON.parse(fs.readFileSync(explanationsFile, 'utf8'));
        }
        // Build repo-level explanation map
        const repoExplanations = {};
        for (const expKey of Object.keys(explanations)) {
            const repoName = expKey.replace(/_patch\.json$/i, '').toLowerCase();
            repoExplanations[repoName] = {
                explanation: explanations[expKey].explanation,
                commit_message: explanations[expKey].commit_message,
                cwe: explanations[expKey]['CWE-id']
            };
        }
        // Load found_lines.json file for getting the code lines which should be highlighted
        const allFiles = fs.readdirSync(resultsPath).filter(f => f.endsWith('.json') && f !== 'explanations.json' && f !== 'relevant_lines.json' && f !== 'commits_dataset_test.json');
        const entries = [];
        for (const jsonFile of allFiles) {
            try {
                const content = fs.readFileSync(path.join(resultsPath, jsonFile), 'utf8');
                const parsed = JSON.parse(content);
                for (const repo of Object.keys(parsed)) {
                    const files = parsed[repo];
                    for (const filePath of Object.keys(files)) {
                        const arr = files[filePath];
                        for (const item of arr) {
                            entries.push({
                                repo,
                                file: item.file,
                                startLine: item.found_lines - 1,
                                endLine: item.found_lines - 1,
                                snippet: item.line
                            });
                        }
                    }
                }
            }
            catch (err) {
                console.warn('Failed reading', jsonFile, err);
            }
        }
        const panel = vscode.window.createWebviewPanel('cweExplorer', 'CWE Vulnerability Explanation', vscode.ViewColumn.One, { enableScripts: true, localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, 'media'))] });
        panel.webview.html = getWebviewContent(panel.webview, context.extensionPath);
        panel.webview.onDidReceiveMessage(async (msg) => {
            if (msg.command === 'openFile') {
                const target = msg.payload;
                let filePath = target.file;
                if (!path.isAbsolute(filePath)) {
                    filePath = path.join(defaultFolder, filePath);
                }
                try {
                    const doc = await vscode.workspace.openTextDocument(filePath);
                    const editor = await vscode.window.showTextDocument(doc);
                    const lineLength = editor.document.lineAt(target.startLine).range.end.character;
                    const start = new vscode.Position(target.startLine, 0);
                    const end = new vscode.Position(target.startLine, lineLength);
                    editor.setDecorations(vulnerableLineDecoration, [new vscode.Range(start, end)]);
                    editor.revealRange(new vscode.Range(start, end), vscode.TextEditorRevealType.InCenter);
                    editor.selection = new vscode.Selection(start, end);
                    const repoName = target.repo.toLowerCase();
                    const expKey = Object.keys(repoExplanations).find(k => repoName.includes(k));
                    const explanation = expKey ? repoExplanations[expKey] : null;
                    if (explanation) {
                        vscode.commands.executeCommand('cweExplorer.showExplanation', {
                            title: repoName,
                            explanation: explanation.explanation,
                            commit_message: explanation.commit_message,
                            cwe: explanations[`${repoName}_patch.json`]?.["CWE-id"]
                        });
                    }
                    if (explanation) {
                        const hover = new vscode.MarkdownString(`**${explanation.cwe.join(', ') || []}**\n\n${explanation.explanation}`);
                        hover.isTrusted = true;
                        editor.setDecorations(vulnerableLineDecoration, [
                            { range: new vscode.Range(start, end), hoverMessage: hover }
                        ]);
                    }
                }
                catch (err) {
                    vscode.window.showErrorMessage('Could not open file: ' + filePath);
                }
            }
            else if (msg.command === 'requestData') {
                panel.webview.postMessage({ command: 'setData', payload: { entries, repoExplanations } });
            }
        });
    });
    // const showExplanation = vscode.commands.registerCommand('cweExplorer.showExplanation', (result) => {
    // 	if (!result) return;
    // 	const panel = vscode.window.createWebviewPanel(
    // 		'cweExplanationDetails',
    // 		`CWE: ${result.title}`,
    // 		vscode.ViewColumn.Beside,
    // 		{ enableScripts: true }
    // 	);
    // 	panel.webview.html = getExplanationWebviewContent(result);
    // });
    // context.subscriptions.push(showExplanation);
    context.subscriptions.push(disposable);
}
function deactivate() { }
function getWebviewContent(webview, extensionPath) {
    const htmlPath = path.join(extensionPath, 'media', 'webview.html');
    let html = fs.readFileSync(htmlPath, 'utf8');
    const mediaUri = webview.asWebviewUri(vscode.Uri.file(path.join(extensionPath, 'media')));
    html = html.replace(/vscode-resource:/g, mediaUri.toString());
    return html;
}
function getExplanationWebviewContent(result) {
    return /* html */ `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${result.title}</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background-color: #1e1e1e;
                color: #d4d4d4;
                padding: 16px;
            }
            h2 {
                color: #4ec9b0;
                margin-bottom: 10px;
            }
            pre {
                background: #252526;
                padding: 12px;
                border-left: 3px solid #d7ba7d;
                white-space: pre-wrap;
                border-radius: 4px;
                color: #dcdcaa;
            }
            .commit {
                color: #9cdcfe;
                font-style: italic;
                margin-top: 8px;
            }
            .cwe {
                background: #333;
                color: #ce9178;
                display: inline-block;
                padding: 2px 6px;
                margin-top: 8px;
                border-radius: 4px;
                font-size: 0.85em;
            }
        </style>
    </head>
    <body>
        <h2>${result.title}</h2>
        ${result.cwe ? result.cwe.map(id => `<div class="cwe">${id}</div>`).join(' ') : ''}
        <pre>${result.explanation}</pre>
        ${result.commit_message ? `<div class="commit">Commit: ${result.commit_message}</div>` : ''}
    </body>
    </html>
    `;
}
//# sourceMappingURL=extension.js.map