mod search;

use anyhow::{Context, Result};
use lsp_client::{LspClient, transport::io_transport};
use regex_lite::Regex;
use std::path::Path;
use std::sync::OnceLock;
use std::{path::PathBuf, process::Stdio, str::FromStr};
use tokio::{process::Command, sync::oneshot};
use tracing::{debug, error, warn};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{fmt, prelude::*};

static LOGRUS_FUNC_RE: OnceLock<Regex> = OnceLock::new();
static WITH_FIELD_FUNC_RE: OnceLock<Regex> = OnceLock::new();

fn logrus_func_regex() -> &'static Regex {
    LOGRUS_FUNC_RE.get_or_init(|| {
        Regex::new(r"func\s\(\w+\s\*logrus\.Entry\)\s(Debug|Info|Warn|Error|Fatal|Panic|Debugf|Infof|Warnf|Errorf|Fatalf|Panicf)\(\w+\s\.\.\.interface\{\}\)").unwrap()
    })
}
fn with_field_func_regex() -> &'static Regex {
    WITH_FIELD_FUNC_RE.get_or_init(|| {
        Regex::new(r"func\s\(\w+\s\*logrus\.Entry\)\sWithField\(\w+\sstring,\s\w+\sinterface\{\}\)\s\*logrus\.Entry").unwrap()
    })
}

#[derive(Debug)]
struct LoggingInvocation {
    column_end: usize,
    column_start: usize,
    level: LoggingInvocationLevel,
    line_end: usize,
    line_start: usize,
    message: String,
}

#[derive(Debug)]
struct WithFieldInvocation {
    column_end: usize,
    column_start: usize,
    key: String,
    line_end: usize,
    line_start: usize,
    value: String,
}

#[derive(Debug)]
struct EntryVariable {
    column_end: usize,
    column_start: usize,
    line_end: usize,
    line_start: usize,
    name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoggingInvocationLevel {
    Debug,
    Debugf,
    Info,
    Infof,
    Warn,
    Warnf,
    Error,
    Errorf,
    Fatal,
    Fatalf,
    Panic,
    Panicf,
}
impl std::str::FromStr for LoggingInvocationLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Debug" => Ok(LoggingInvocationLevel::Debug),
            "Debugf" => Ok(LoggingInvocationLevel::Debugf),
            "Info" => Ok(LoggingInvocationLevel::Info),
            "Infof" => Ok(LoggingInvocationLevel::Infof),
            "Warn" => Ok(LoggingInvocationLevel::Warn),
            "Warnf" => Ok(LoggingInvocationLevel::Warnf),
            "Error" => Ok(LoggingInvocationLevel::Error),
            "Errorf" => Ok(LoggingInvocationLevel::Errorf),
            "Fatal" => Ok(LoggingInvocationLevel::Fatal),
            "Fatalf" => Ok(LoggingInvocationLevel::Fatalf),
            "Panic" => Ok(LoggingInvocationLevel::Panic),
            "Panicf" => Ok(LoggingInvocationLevel::Panicf),
            _ => Err(()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    if args.len() != 2 {
        eprintln!(
            "Usage: {} <absolute_path_to_go_workspace>",
            args.next().unwrap()
        );
        std::process::exit(1);
    }
    args.next(); // Skip the program name

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(LevelFilter::INFO)
        .init();

    let path_str = args.next().unwrap();
    let path = PathBuf::from_str(&path_str)?;
    let _ = std::env::set_current_dir(path.clone());
    let mut child = Command::new("gopls")
        .current_dir(path.clone())
        .arg("serve")
        .arg("-logfile")
        .arg("patgopls.log")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to spawn gopls")?;
    let stdin = child.stdin.take().context("missing stdin")?;
    let stdout = child.stdout.take().context("missing stdout")?;

    let (tx, rx) = io_transport(stdin, stdout);

    let client = LspClient::new(tx, rx);

    let source_uri = lsp_types::Uri::from_str(format!("file://{}", path_str).as_str())?;
    // Channel to wait for rust-analyzer to finish indexing the workspace.
    let (indexed_tx, indexed_rx) = oneshot::channel();
    let mut subscription = client
        .subscribe_to_method::<lsp_types::notification::ShowMessage>()
        .await?;
    tokio::spawn(async move {
        println!("Waiting for indexing to finish...");
        while let Some(msg) = subscription.next().await {
            let params = msg.unwrap();
            println!("Progress: {:?}", params);
            if params.message == "Finished loading packages." {
                // Notify that indexing is done.
                indexed_tx.send(()).unwrap();
                break;
            }
        }
        subscription.unsubscribe().await.unwrap();
    });
    let mut log_message_subscription = client
        .subscribe_to_method::<lsp_types::notification::LogMessage>()
        .await?;
    tokio::spawn(async move {
        while let Some(msg) = log_message_subscription.next().await {
            let params = msg.unwrap();
            info!("Log message: {:?}", params);
        }
    });

    let initialize = lsp_types::InitializeParams {
        root_path: Some(path_str.to_string()),
        root_uri: Some(source_uri.clone()),
        capabilities: lsp_types::ClientCapabilities {
            text_document: Some(lsp_types::TextDocumentClientCapabilities {
                references: Some(lsp_types::ReferenceClientCapabilities {
                    dynamic_registration: Some(true),
                }),
                hover: Some(lsp_types::HoverClientCapabilities {
                    dynamic_registration: Some(false),
                    content_format: Some(vec![lsp_types::MarkupKind::PlainText]),
                }),
                ..Default::default()
            }),
            workspace: Some(lsp_types::WorkspaceClientCapabilities {
                workspace_folders: Some(true),
                ..Default::default()
            }),
            window: Some(lsp_types::WindowClientCapabilities {
                work_done_progress: Some(false),
                show_message: Some(lsp_types::ShowMessageRequestClientCapabilities {
                    message_action_item: Some(lsp_types::MessageActionItemCapabilities {
                        additional_properties_support: Some(false),
                    }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
        workspace_folders: Some(vec![lsp_types::WorkspaceFolder {
            name: path_str.to_string(),
            uri: source_uri,
        }]),
        ..Default::default()
    };
    let a = client.initialize(initialize).await?;
    client.initialized().await?;

    println!("Initialized gopls");

    // Wait to finish indexing the workspac.
    indexed_rx
        .await
        .context("failed to receive indexing notification")?;

    // Use os.WalkDir to find all Go files in the workspace.
    let go_files = std::fs::read_dir(path)
        .context("failed to read directory")?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "go"))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    for go_file in go_files {
        let log_invocations = get_logging_invocations(go_file.as_path(), &client).await;
        let with_field_invocations = get_with_field_invocations(go_file.as_path(), &client).await;
        let entry_variables = get_entry_variables(go_file.as_path(), &client).await;
    }

    client.shutdown().await?;
    client.exit().await?;
    child.wait().await?;

    Ok(())
}
async fn lsp_references(
    client: &LspClient,
    uri: &lsp_types::Uri,
    line: usize,
    column: usize,
) -> Result<Vec<lsp_types::Location>> {
    let references = client
        .send_request::<lsp_types::request::References>(lsp_types::ReferenceParams {
            text_document_position: lsp_types::TextDocumentPositionParams {
                text_document: lsp_types::TextDocumentIdentifier { uri: uri.clone() },
                position: lsp_types::Position {
                    line: line as u32,
                    character: column as u32,
                },
            },
            context: lsp_types::ReferenceContext {
                include_declaration: false,
            },
            work_done_progress_params: lsp_types::WorkDoneProgressParams {
                work_done_token: None,
            },
            partial_result_params: lsp_types::PartialResultParams {
                partial_result_token: None,
            },
        })
        .await?;
    Ok(references.unwrap_or_default())
}

async fn lsp_hover(
    client: &LspClient,
    uri: &lsp_types::Uri,
    line: usize,
    column: usize,
) -> Result<lsp_types::Hover> {
    let hover = client
        .send_request::<lsp_types::request::HoverRequest>(lsp_types::HoverParams {
            text_document_position_params: lsp_types::TextDocumentPositionParams {
                text_document: lsp_types::TextDocumentIdentifier { uri: uri.clone() },
                position: lsp_types::Position {
                    line: line as u32,
                    character: column as u32,
                },
            },
            work_done_progress_params: lsp_types::WorkDoneProgressParams {
                work_done_token: None,
            },
        })
        .await?;
    if hover.is_none() {
        return Err(anyhow::anyhow!("No hover information found"));
    }
    Ok(hover.unwrap())
}

async fn get_entry_variables(go_file: &Path, client: &LspClient) -> Vec<EntryVariable> {
    let mut variables = vec![];
    let go_file_str = go_file.to_string_lossy();
    let content = std::fs::read_to_string(&go_file);
    if content.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?content.err().unwrap(),
            "Failed to read file",
        );
        return variables;
    }
    let content = content.unwrap();
    let uri = lsp_types::Uri::from_str(&format!("file://{}", go_file_str));
    if uri.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?uri.err().unwrap(),
            "Failed to create URI for Language Server Protocol",
        );
        return variables;
    }
    let uri = uri.unwrap();
    let ranges = search::find_functions_returning_logrus_entry(&content, &go_file_str);
    if ranges.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?ranges.err().unwrap(),
            "Failed to find logging function invocations",
        );
        return variables;
    }
    let ranges = ranges.unwrap();
    for range in ranges {
        let references = lsp_references(client, &uri, range.line_start, range.column_start).await;
        if references.is_err() {
            warn!(
                file = go_file.to_str(),
                line_start = range.line_start,
                column_start = range.column_start,
                cause = ?references.err().unwrap(),
                "Failed to get references",
            );
            continue;
        }
        let references = references.unwrap();

        let r = references[0].clone();
        info!(
            file = r.uri.to_string().as_str(),
            line_start = r.range.start.line,
            column_start = r.range.start.character,
            "Found references: {:?}",
            r,
        );
        let ref_filepath = r.uri.path().to_string();
        let content = std::fs::read_to_string(&ref_filepath);
        if content.is_err() {
            warn!(
                file = r.uri.to_string(),
                cause = ?content.err().unwrap(),
                "Failed to read file for references",
            );
            continue;
        }
        let content = content.unwrap();
        let semantic_parent_range = search::find_semantic_parent_range_for_logrus_reference(
            &content,
            r.range.start.line as usize,
            r.range.end.line as usize,
            r.range.start.character as usize,
            r.range.end.character as usize,
            &ref_filepath,
        );
        if semantic_parent_range.is_err() {
            warn!(
                file = r.uri.to_string(),
                cause = ?semantic_parent_range.err().unwrap(),
                "Failed to find semantic parent range for logrus reference",
            );
            continue;
        }
        let semantic_parent_range = semantic_parent_range.unwrap();
        dbg!(&semantic_parent_range);
        if let search::TreeSitterSemanticParentRange::ShortVarDeclaration(line, column) =
            semantic_parent_range
        {
            let references = lsp_references(client, &r.uri.clone(), line, column).await;
            if references.is_err() {
                warn!(
                    file = go_file.to_str(),
                    line_start = range.line_start,
                    column_start = range.column_start,
                    cause = ?references.err().unwrap(),
                    "Failed to get references",
                );
                continue;
            }
            let references = references.unwrap();

            let r = references[0].clone();
            info!(
                file = r.uri.to_string().as_str(),
                line_start = r.range.start.line,
                column_start = r.range.start.character,
                "Found second references: {:?}",
                r,
            );
        }
    }

    variables
}

async fn get_logging_invocations(go_file: &Path, client: &LspClient) -> Vec<LoggingInvocation> {
    let mut invocations = vec![];
    let go_file_str = go_file.to_string_lossy();
    let content = std::fs::read_to_string(go_file);
    if content.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?content.err().unwrap(),
            "Failed to read file",
        );
        return invocations;
    }
    let content = content.unwrap();
    let uri = lsp_types::Uri::from_str(&format!("file://{}", go_file_str));
    if uri.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?uri.err().unwrap(),
            "Failed to create URI for Language Server Protocol",
        );
        return invocations;
    }
    let uri = uri.unwrap();
    let ranges = search::find_logging_function(&content, &go_file_str);
    if ranges.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?ranges.err().unwrap(),
            "Failed to find logging function invocations",
        );
        return invocations;
    }
    let ranges = ranges.unwrap();
    for logging_function in ranges {
        let hover = lsp_hover(
            client,
            &uri,
            logging_function.line_start,
            logging_function.column_start,
        )
        .await;
        if hover.is_err() {
            warn!(
                file = go_file.to_str(),
                line_start = logging_function.line_start,
                column_start = logging_function.column_start,
                cause = ?hover.err().unwrap(),
                "Failed to get hover information",
            );
            continue;
        }
        let hover = hover.unwrap();
        if let lsp_types::HoverContents::Markup(markup_content) = hover.contents {
            if markup_content.kind == lsp_types::MarkupKind::PlainText {
                let first_line = markup_content.value.lines().next();
                if first_line.is_none() {
                    continue;
                }
                let first_line = first_line.unwrap();
                let captured = logrus_func_regex()
                    .captures(first_line)
                    .iter()
                    .filter_map(|captures| captures.get(1).map(|m| m.as_str()))
                    .collect::<Vec<_>>();
                if captured.len() != 1 {
                    continue;
                }
                let level = captured[0].parse::<LoggingInvocationLevel>();
                if level.is_err() {
                    error!(
                            file = go_file.to_str(),
                    line_start = logging_function.line_start,
                    column_start = logging_function.column_start,
                            cause = ?level.err().unwrap(),
                            "Failed to parse logging level. This is a bug. Please report it.",
                        );
                    continue;
                }
                let level = level.unwrap();
                invocations.push(LoggingInvocation {
                    line_start: logging_function.line_start + 1,
                    column_start: logging_function.column_start,
                    line_end: logging_function.line_end + 1,
                    column_end: logging_function.column_end,
                    level,
                    message: logging_function.arguments.clone(),
                });
            }
        }
    }

    invocations
}

async fn get_with_field_invocations(
    go_file: &Path,
    client: &LspClient,
) -> Vec<WithFieldInvocation> {
    let mut invocations = vec![];
    let go_file_str = go_file.to_string_lossy();
    let content = std::fs::read_to_string(&go_file);
    if content.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?content.err().unwrap(),
            "Failed to read file",
        );
        return invocations;
    }
    let content = content.unwrap();
    let uri = lsp_types::Uri::from_str(&format!("file://{}", go_file_str));
    if uri.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?uri.err().unwrap(),
            "Failed to create URI for Language Server Protocol",
        );
        return invocations;
    }
    let uri = uri.unwrap();
    let ranges = search::find_with_field(&content, &go_file_str);
    if ranges.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?ranges.err().unwrap(),
            "Failed to find logging function invocations",
        );
        return invocations;
    }
    let ranges = ranges.unwrap();
    for with_field_function in ranges {
        let hover = client
            .send_request::<lsp_types::request::HoverRequest>(lsp_types::HoverParams {
                text_document_position_params: lsp_types::TextDocumentPositionParams {
                    text_document: lsp_types::TextDocumentIdentifier { uri: uri.clone() },
                    position: lsp_types::Position {
                        line: with_field_function.line_start as u32,
                        character: with_field_function.column_start as u32,
                    },
                },
                work_done_progress_params: lsp_types::WorkDoneProgressParams {
                    work_done_token: None,
                },
            })
            .await;
        let hover = lsp_hover(
            client,
            &uri,
            with_field_function.line_start,
            with_field_function.column_start,
        )
        .await;
        if hover.is_err() {
            warn!(
                file = go_file.to_str(),
                line_start = with_field_function.line_start,
                column_start = with_field_function.column_start,
                cause = ?hover.err().unwrap(),
                "Failed to get hover information",
            );
            continue;
        }
        let hover = hover.unwrap();
        if let lsp_types::HoverContents::Markup(markup_content) = hover.contents {
            if markup_content.kind == lsp_types::MarkupKind::PlainText {
                let first_line = markup_content.value.lines().next();
                if first_line.is_none() {
                    continue;
                }
                let first_line = first_line.unwrap();
                let is_match = with_field_func_regex().is_match(first_line);
                if is_match {
                    invocations.push(WithFieldInvocation {
                        column_end: with_field_function.column_end,
                        column_start: with_field_function.column_start,
                        key: with_field_function.key,
                        line_end: with_field_function.line_end + 1,
                        line_start: with_field_function.line_start + 1,
                        value: with_field_function.value,
                    });
                }
            }
        }
    }

    invocations
}
