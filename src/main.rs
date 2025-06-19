mod search;

use anyhow::{Context, Result};
use lsp_client::{LspClient, transport::io_transport};
use regex_lite::Regex;
use std::collections::HashMap;
use std::hash::Hash;
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
    uri: String,
}

#[derive(Debug)]
struct LoggerAlias {
    identifier: LoggerIdentifier,
    parent: Option<LoggerIdentifier>,
}

#[derive(Debug, Clone)]
struct LoggerIdentifier {
    column_end: usize,
    column_start: usize,
    line_end: usize,
    line_start: usize,
    uri: String,
}

#[derive(Debug)]
struct WithFieldInvocation {
    column_end: usize,
    column_start: usize,
    key: String,
    line_end: usize,
    line_start: usize,
    value: String,
    uri: String,
}

#[derive(Debug)]
struct EntryVariable {
    column_end: usize,
    column_start: usize,
    line_end: usize,
    line_start: usize,
    name: String,
}

struct FinializedLog {
    message: String,
    level: LoggingInvocationLevel,
    fields: Vec<FinalizedLoggingField>,
}
struct FinalizedLoggingField {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PointMarker {
    Logger,
    Field,
    Message,
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
    client.initialize(initialize).await?;
    client.initialized().await?;

    println!("Initialized gopls");

    // Wait to finish indexing the workspac.
    indexed_rx
        .await
        .context("failed to receive indexing notification")?;

    let mut log_invocations = vec![];
    let mut with_field_invocations = vec![];
    let mut logger_aliases = vec![];
    let go_files = std::fs::read_dir(path)
        .context("failed to read directory")?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "go"))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    for go_file in go_files {
        let inner_log_invocations = get_logging_invocations(go_file.as_path(), &client).await;
        let inner_with_field_invocations =
            get_with_field_invocations(go_file.as_path(), &client).await;
        let inner_logger_aliases = get_logger_aliases(go_file.as_path(), &client).await;

        log_invocations.extend(inner_log_invocations);
        with_field_invocations.extend(inner_with_field_invocations);
        logger_aliases.extend(inner_logger_aliases);
    }
    dbg!(&logger_aliases);
    let mut logger_alias_markers = HashMap::new();
    for alias in &logger_aliases {
        logger_alias_markers.insert(
            format!("{}:{}", alias.identifier.uri, alias.identifier.line_start),
            PointMarker::Logger,
        );
    }

    // Build direct state for each logger alias
    let get_logger_state_for_identifier =
        |identifier: &LoggerIdentifier| -> HashMap<String, String> {
            let mut state: HashMap<String, String> = HashMap::new();

            let mut interesting_fields = with_field_invocations
                .iter()
                .filter(|inv| inv.uri == identifier.uri)
                .filter(|inv| inv.line_start >= identifier.line_start)
                .collect::<Vec<_>>();
            interesting_fields.sort_by(|a, b| {
                (a.line_start, a.column_start).cmp(&(b.line_start, b.column_start))
            });
            let mut current_point = (identifier.line_start, identifier.column_start);
            for inv in &interesting_fields {
                // WithField is on the same line as the alias
                if current_point.0 == inv.line_start && current_point.1 <= inv.column_start {
                    // We can consider this WithField invocation as a field for the alias.
                    state.insert(inv.key.clone(), inv.value.clone());
                    current_point = (inv.line_start, inv.column_start);
                }
                if current_point.0 + 1 == inv.line_start
                    && !logger_alias_markers
                        .contains_key(&format!("{}:{}", inv.uri, inv.line_start))
                {
                    // In the case where this is None, we can consider this WithField invocation
                    // applying to the same logger.

                    state.insert(inv.key.clone(), inv.value.clone());
                    current_point = (inv.line_start, inv.column_start);
                }
            }
            state
        };
    let mut logger_states: HashMap<String, HashMap<String, String>> = HashMap::new();
    for alias in &logger_aliases {
        let mut state = HashMap::new();
        let mut parent_option = &alias.parent;
        while let Some(parent) = parent_option {
            let new_parent = logger_aliases.iter().find(|a| {
                a.identifier.uri == parent.uri
                    && a.identifier.line_start == parent.line_start
                    && a.identifier.column_start == parent.column_start
            });
            if new_parent.is_none() {
                parent_option = &None;
            } else {
                parent_option = &new_parent.unwrap().parent;
            }
            let parent_state = get_logger_state_for_identifier(parent);
            state.extend(parent_state);
        }
        let this_state = get_logger_state_for_identifier(&alias.identifier);
        state.extend(this_state);
        let logger_key = format!(
            "{}:{}:{}",
            alias.identifier.uri, alias.identifier.line_start, alias.identifier.column_start
        );
        logger_states.entry(logger_key).or_default().extend(state);
    }
    dbg!(&logger_states);

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

async fn get_logger_aliases(go_file: &Path, client: &LspClient) -> Vec<LoggerAlias> {
    let mut logger_aliases = vec![];
    let go_file_str = go_file.to_string_lossy();
    let content = std::fs::read_to_string(go_file);
    if content.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?content.err().unwrap(),
            "Failed to read file",
        );
        return logger_aliases;
    }
    let content = content.unwrap();
    let uri = lsp_types::Uri::from_str(&format!("file://{}", go_file_str));
    if uri.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?uri.err().unwrap(),
            "Failed to create URI for Language Server Protocol",
        );
        return logger_aliases;
    }
    let uri = uri.unwrap();
    let ranges = search::find_functions_returning_logrus_entry(&content, &go_file_str);
    if ranges.is_err() {
        error!(
            file = go_file.to_str(),
            cause = ?ranges.err().unwrap(),
            "Failed to find logging function invocations",
        );
        return logger_aliases;
    }
    let ranges = ranges.unwrap();
    for range in ranges {
        let logger_parent = LoggerIdentifier {
            column_end: range.column_end,
            column_start: range.column_start,
            line_end: range.line_end,
            line_start: range.line_start,
            uri: uri.to_string(),
        };
        let mut resolved_references = vec![];
        let inner_logger_aliases =
            resolve_loggers(client, logger_parent, true, &mut resolved_references).await;
        logger_aliases.extend(inner_logger_aliases);
    }

    logger_aliases
}

async fn resolve_loggers(
    client: &LspClient,
    parent: LoggerIdentifier,
    root: bool,
    resolved_references: &mut Vec<String>,
) -> Vec<LoggerAlias> {
    Box::pin(async move {
        let mut boxed_logger_aliases = vec![];
        if resolved_references.contains(&format!(
            "{}:{}:{}",
            parent.uri, parent.line_start, parent.column_start
        )) {
            debug!(
                file = parent.uri.to_string().as_str(),
                line_start = parent.line_start,
                column_start = parent.column_start,
                "Skipping already resolved reference: {:?}",
                parent,
            );
            return boxed_logger_aliases;
        }
        let uri = lsp_types::Uri::from_str(&parent.uri).unwrap();
        let references = lsp_references(client, &uri, parent.line_start, parent.column_start).await;
        if references.is_err() {
            warn!(
                file = parent.uri.to_string().as_str(),
                line_start = parent.line_start,
                column_start = parent.column_start,
                cause = ?references.err().unwrap(),
                "Failed to get references",
            );
            return boxed_logger_aliases;
        }
        let references = references.unwrap();
        for lsp_ref in references {
            resolved_references.push(format!(
                "{}:{}:{}",
                *lsp_ref.uri, lsp_ref.range.start.line, lsp_ref.range.start.character
            ));
            debug!(
                file = lsp_ref.uri.to_string().as_str(),
                line_start = lsp_ref.range.start.line,
                column_start = lsp_ref.range.start.character,
                "Found references: {:?}",
                lsp_ref,
            );
            let ref_filepath = lsp_ref.uri.path().to_string();
            let content = std::fs::read_to_string(&ref_filepath);
            if content.is_err() {
                warn!(
                    file = lsp_ref.uri.to_string(),
                    cause = ?content.err().unwrap(),
                    "Failed to read file for references",
                );
                continue;
            }
            let content = content.unwrap();
            let semantic_parent_range = search::find_semantic_parent_range_for_logrus_reference(
                &content,
                lsp_ref.range.start.line as usize,
                lsp_ref.range.end.line as usize,
                lsp_ref.range.start.character as usize,
                lsp_ref.range.end.character as usize,
                &ref_filepath,
            );
            if semantic_parent_range.is_err() {
                warn!(
                    file = lsp_ref.uri.to_string(),
                    cause = ?semantic_parent_range.err().unwrap(),
                    "Failed to find semantic parent range for logrus reference",
                );
                continue;
            }
            let semantic_parent_range = semantic_parent_range.unwrap();
            match semantic_parent_range {
                search::TreeSitterSemanticParentRange::ShortVarDeclaration(range) => {
                    let references =
                        lsp_references(client, &lsp_ref.uri, range.line_start, range.column_start)
                            .await;
                    if references.is_err() {
                        warn!(
                            file = lsp_ref.uri.to_string(),
                            line_start = lsp_ref.range.start.line,
                            column_start = lsp_ref.range.start.character,
                            cause = ?references.err().unwrap(),
                            "Failed to get references",
                        );
                        return boxed_logger_aliases;
                    }
                    let references = references.unwrap();

                    for lsp_ref in references {
                        if resolved_references.contains(&format!(
                            "{}:{}:{}",
                            *lsp_ref.uri, lsp_ref.range.start.line, lsp_ref.range.start.character
                        )) {
                            debug!(
                                file = lsp_ref.uri.to_string().as_str(),
                                line_start = lsp_ref.range.start.line,
                                column_start = lsp_ref.range.start.character,
                                "Skipping already resolved reference: {:?}",
                                lsp_ref,
                            );
                            continue;
                        }
                        let parent = LoggerIdentifier {
                            column_end: range.column_end,
                            column_start: range.column_start,
                            line_end: range.line_end,
                            line_start: range.line_start,
                            uri: lsp_ref.uri.to_string(),
                        };
                        let inner_aliases =
                            resolve_loggers(client, parent, false, resolved_references).await;
                        boxed_logger_aliases.extend(inner_aliases);
                    }
                }
                search::TreeSitterSemanticParentRange::Identity => {
                    boxed_logger_aliases.push(LoggerAlias {
                        identifier: LoggerIdentifier {
                            column_end: lsp_ref.range.end.character as usize,
                            column_start: lsp_ref.range.start.character as usize,
                            line_end: lsp_ref.range.end.line as usize,
                            line_start: lsp_ref.range.start.line as usize,
                            uri: lsp_ref.uri.to_string(),
                        },
                        parent: if root { None } else { Some(parent.clone()) },
                    });
                }
                search::TreeSitterSemanticParentRange::AssignmentStatement(range) => {
                    boxed_logger_aliases.push(LoggerAlias {
                        identifier: LoggerIdentifier {
                            column_end: range.column_end,
                            column_start: range.column_start,
                            line_end: range.line_end,
                            line_start: range.line_start,
                            uri: range.uri.clone(),
                        },
                        parent: if root {
                            None
                        } else {
                            Some(LoggerIdentifier {
                                column_end: lsp_ref.range.end.character as usize,
                                column_start: lsp_ref.range.start.character as usize,
                                line_end: lsp_ref.range.end.line as usize,
                                line_start: lsp_ref.range.start.line as usize,
                                uri: lsp_ref.uri.to_string(),
                            })
                        },
                    });
                }
            }
        }
        boxed_logger_aliases
    })
    .await
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
                    line_start: logging_function.line_start,
                    column_start: logging_function.column_start,
                    line_end: logging_function.line_end,
                    column_end: logging_function.column_end,
                    level,
                    message: logging_function.arguments.clone(),
                    uri: uri.to_string(),
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
                        line_end: with_field_function.line_end,
                        line_start: with_field_function.line_start,
                        value: with_field_function.value,
                        uri: uri.to_string(),
                    });
                } else {
                    debug!(
                        file = go_file.to_str(),
                        line_start = with_field_function.line_start,
                        column_start = with_field_function.column_start,
                        line = first_line,
                        "Found WithField invocation, but it does not match the expected pattern",
                    );
                }
            }
        }
    }

    invocations
}
