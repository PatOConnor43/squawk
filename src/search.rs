use anyhow::Ok;
use tracing::{debug, info};
use tree_sitter::StreamingIterator;
use tree_sitter_go::LANGUAGE;

pub fn find_functions_returning_logrus_entry(
    content: &str,
    filename: &str,
) -> Result<Vec<TreeSitterFunctionReturningLogrusEntry>, anyhow::Error> {
    let mut results: Vec<TreeSitterFunctionReturningLogrusEntry> = vec![];
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&LANGUAGE.into())?;
    let tree = parser.parse(content, None);
    if tree.is_none() {
        return Ok(vec![]);
    }
    let tree = tree.unwrap();
    let query_content = r#"
(function_declaration
  name: (identifier) @function.name
  result: (pointer_type
    (qualified_type
      package: (package_identifier) @package (#eq? @package "logrus")
      name: (type_identifier) @type (#eq? @type "Entry")))
  body: (block) @function.body
)
    "#;
    let query = tree_sitter::Query::new(&LANGUAGE.into(), query_content)?;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());

    while let Some(m) = matches.next() {
        let function_name_node = m.nodes_for_capture_index(0).next();
        if function_name_node.is_none() {
            continue;
        }
        let function_name_node = function_name_node.unwrap();
        let (line_start, column_start, line_end, column_end) =
            byte_range_to_position(content, &function_name_node.byte_range());
        results.push(TreeSitterFunctionReturningLogrusEntry {
            filename: filename.to_string(),
            line_start,
            line_end,
            column_start,
            column_end,
            function_name: content[function_name_node.byte_range()].to_string(),
        });
    }

    Ok(results)
}
pub fn find_semantic_parent_range_for_logrus_reference(
    content: &str,
    line_start: usize,
    line_end: usize,
    column_start: usize,
    column_end: usize,
    filename: &str,
) -> Result<TreeSitterSemanticParentRange, anyhow::Error> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&LANGUAGE.into())?;
    let tree = parser.parse(content, None);
    if tree.is_none() {
        let e =
            anyhow::anyhow!("Failed to parse content with tree-sitter for semantic parent range");
        return Err(e);
    }
    let tree = tree.unwrap();
    let start_point = tree_sitter::Point {
        row: line_start,
        column: column_start,
    };
    let end_point = tree_sitter::Point {
        row: line_end,
        column: column_end,
    };
    let node = tree
        .root_node()
        .named_descendant_for_point_range(start_point, end_point);

    if node.is_none() {
        let e = anyhow::anyhow!(
            "Failed to find named descendant for point range: {}:{}-{}:{}",
            line_start,
            column_start,
            line_end,
            column_end
        );
        return Err(e);
    }
    let node = node.unwrap();
    if node.kind() != "identifier" {
        return Ok(TreeSitterSemanticParentRange::Identity);
    }

    // The only pathway that is currently supported is go code that looks like this:
    // 	log := logger()

    let original_node_byte_range = node.byte_range();
    let mut n = node.parent();
    let mut found_short_var_declaration = false;
    let mut found_assignment_statement = None;
    while n.is_some() {
        let inner = n.unwrap();
        found_short_var_declaration =
            inner.child_by_field_name("right").is_some() && inner.kind() == "short_var_declaration";
        found_assignment_statement = || -> Option<TreeSitterRange> {
            inner.child_by_field_name("left")?;
            inner.child_by_field_name("right")?;
            inner.child_by_field_name("operator")?;
            if inner.kind() != "assignment_statement" {
                return None;
            }
            let byte_range = inner.child_by_field_name("left").unwrap().byte_range();
            let c = &content[original_node_byte_range.clone()];
            dbg!(c);
            let c = &content[inner.byte_range()];
            dbg!(c);
            let range = byte_range_to_position(content, &original_node_byte_range);
            Some(TreeSitterRange {
                line_start: range.0,
                line_end: range.2,
                column_start: range.1,
                column_end: range.3,
                uri: format!("file://{}", filename),
            })
        }();
        if found_short_var_declaration || found_assignment_statement.is_some() {
            break;
        }
        n = inner.parent();
    }
    if found_short_var_declaration {
        let inner = n.unwrap();
        return Ok(TreeSitterSemanticParentRange::ShortVarDeclaration(
            TreeSitterRange {
                line_start: inner.start_position().row,
                line_end: inner.end_position().row,
                column_start: inner.start_position().column,
                column_end: inner.end_position().column,
                uri: format!("file://{}", filename),
            },
        ));
    } else if found_assignment_statement.is_some() {
        return Ok(TreeSitterSemanticParentRange::AssignmentStatement(
            found_assignment_statement.unwrap(),
        ));
    }

    Ok(TreeSitterSemanticParentRange::Identity)
}

pub fn find_fields(
    content: &str,
    function_name: &str,
) -> Result<Vec<(usize, usize)>, anyhow::Error> {
    let mut results: Vec<(usize, usize)> = vec![];
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&LANGUAGE.into())?;
    let tree = parser.parse(content, None);
    if tree.is_none() {
        return Ok(vec![]);
    }
    let tree = tree.unwrap();
    let bare_function_call_query = format!(
        r#"
(
  short_var_declaration
  left: (expression_list (identifier) @short_var_name)
  right: (expression_list (
                           call_expression
                           function: (identifier) @short_var_function_name
                           ) (#eq? @short_var_function_name "{function_name}")
         )
)
"#
    );
    let query = tree_sitter::Query::new(&LANGUAGE.into(), bare_function_call_query.as_str())?;
    let mut cursor = tree_sitter::QueryCursor::new();

    // Need to find references for the variable that's created by the short variable declaration
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        println!("{}", m.captures.len());
        for node in m.nodes_for_capture_index(0) {
            let (line_start, column_start, line_end, column_end) =
                byte_range_to_position(content, &node.byte_range());
            println!(
                "Captured node: {:?}, Text: {}, Range: {}:{}-{}:{}",
                node,
                &content[node.byte_range()],
                line_start,
                column_start,
                line_end,
                column_end
            );
        }
    }

    Ok(results)
}

pub fn find_with_field(
    content: &str,
    filename: &str,
) -> Result<Vec<TreeSitterWithFieldFunction>, anyhow::Error> {
    let mut results: Vec<TreeSitterWithFieldFunction> = vec![];
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&LANGUAGE.into())?;
    let tree = parser.parse(content, None);
    if tree.is_none() {
        return Ok(vec![]);
    }
    let tree = tree.unwrap();
    let query_content = r#"
;; This query captures WithField being called on a function invocation like:
;; logger().WithField("key", "value")
(call_expression
  function: (selector_expression
    operand: (call_expression
      arguments: (argument_list
        [(identifier) (raw_string_literal) (interpreted_string_literal)] @arguments.key
        [(identifier) (raw_string_literal) (interpreted_string_literal)] @arguments.value
      )
    )
    field: (field_identifier) @method (#eq? @method "WithField")
  )
)
"#;
    let query = tree_sitter::Query::new(&LANGUAGE.into(), query_content)?;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        let arguments_key_node = m.nodes_for_capture_index(0).next();
        let arguments_value_node = m.nodes_for_capture_index(1).next();
        let method_node = m.nodes_for_capture_index(2).next();

        if arguments_key_node.is_none() || arguments_value_node.is_none() || method_node.is_none() {
            continue;
        }
        let arguments_key_node = arguments_key_node.unwrap();
        let arguments_value_node = arguments_value_node.unwrap();
        let method_node = method_node.unwrap();
        debug!(
            filename = filename,
            key = ?arguments_key_node,
            value = ?arguments_value_node,
            method = ?method_node,
            "Found WithField call"
        );
        let (line_start, column_start, line_end, column_end) =
            byte_range_to_position(content, &method_node.byte_range());
        results.push(TreeSitterWithFieldFunction {
            filename: filename.to_string(),
            line_start,
            line_end,
            column_start,
            column_end,
            key: content[arguments_key_node.byte_range()].to_string(),
            value: content[arguments_value_node.byte_range()].to_string(),
        });
    }
    let query_content = r#"
;; This query captures WithField being called on a struct like:
;; log.WithField("key", "value")
(call_expression
  function: (selector_expression
    field: (field_identifier) @method (#eq? @method "WithField")
  )
  arguments: (argument_list
    (
      [(identifier) (interpreted_string_literal) (raw_string_literal)] @arguments.key
      [(identifier) (interpreted_string_literal) (raw_string_literal)] @arguments.value
    )
  )
)
"#;
    let query = tree_sitter::Query::new(&LANGUAGE.into(), query_content)?;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        let arguments_key_node = m.nodes_for_capture_index(1).next();
        let arguments_value_node = m.nodes_for_capture_index(2).next();
        let method_node = m.nodes_for_capture_index(0).next();

        if arguments_key_node.is_none() || arguments_value_node.is_none() || method_node.is_none() {
            continue;
        }
        let arguments_key_node = arguments_key_node.unwrap();
        let arguments_value_node = arguments_value_node.unwrap();
        let method_node = method_node.unwrap();
        debug!(
            filename = filename,
            key = ?arguments_key_node,
            value = ?arguments_value_node,
            method = ?method_node,
            "Found WithField call"
        );
        let (line_start, column_start, line_end, column_end) =
            byte_range_to_position(content, &method_node.byte_range());
        results.push(TreeSitterWithFieldFunction {
            filename: filename.to_string(),
            line_start,
            line_end,
            column_start,
            column_end,
            key: content[arguments_key_node.byte_range()].to_string(),
            value: content[arguments_value_node.byte_range()].to_string(),
        });
    }

    Ok(results)
}

pub struct TreeSitterLoggingFunction {
    pub filename: String,
    pub line_start: usize,
    pub line_end: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub arguments: String,
}

#[derive(Debug)]
pub struct TreeSitterWithFieldFunction {
    pub filename: String,
    pub line_start: usize,
    pub line_end: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub key: String,
    pub value: String,
}

pub struct TreeSitterFunctionReturningLogrusEntry {
    pub filename: String,
    pub line_start: usize,
    pub line_end: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub function_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeSitterSemanticParentRange {
    ShortVarDeclaration(TreeSitterRange), // (line_start, column_start)
    AssignmentStatement(TreeSitterRange), // (line_start, column_start)
    // Identity is used to signal that this is a terminal node and there is nothing else to find.
    Identity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeSitterRange {
    pub line_start: usize,
    pub line_end: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub uri: String,
}

pub fn find_logging_function(
    content: &str,
    filename: &str,
) -> Result<Vec<TreeSitterLoggingFunction>, anyhow::Error> {
    let mut results: Vec<TreeSitterLoggingFunction> = vec![];
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&LANGUAGE.into())?;
    let tree = parser.parse(content, None);
    if tree.is_none() {
        return Ok(vec![]);
    }
    let tree = tree.unwrap();
    let query_content = r#"
(call_expression
  function: (selector_expression
    field: (field_identifier) @method (#any-of? @method "Debug" "Debugf" "Info" "Infof" "Warn" "Warnf" "Error" "Errorf" "Fatal" "Fatalf" "Panic" "Panicf")
  )
  arguments: (argument_list) @arguments
)
"#;
    let query = tree_sitter::Query::new(&LANGUAGE.into(), query_content)?;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        let method_node = m.nodes_for_capture_index(0).next();
        let arguments_node = m.nodes_for_capture_index(1).next();

        if method_node.is_none() || arguments_node.is_none() {
            continue;
        }
        let method_node = method_node.unwrap();
        let arguments_node = arguments_node.unwrap();

        let (line_start, column_start, line_end, column_end) =
            byte_range_to_position(content, &method_node.byte_range());
        results.push(TreeSitterLoggingFunction {
            filename: filename.to_string(),
            line_start,
            line_end,
            column_start,
            column_end,
            arguments: content[arguments_node.byte_range()].to_string(),
        });
    }

    Ok(results)
}

pub fn byte_range_to_position(
    content: &str,
    byte_range: &std::ops::Range<usize>,
) -> (usize, usize, usize, usize) {
    let mut line_start = 1;
    let mut column_start = 1;
    let mut line_end = 1;
    let mut column_end = 1;
    let mut current_line = 1;
    let mut current_column = 1;

    let mut found_start = false;

    for (i, c) in content.char_indices() {
        if i == byte_range.start {
            line_start = current_line;
            column_start = current_column;
            found_start = true;
        }

        if i == byte_range.end {
            line_end = current_line;
            column_end = current_column;
            break;
        }

        if c == '\n' {
            current_line += 1;
            current_column = 1;
        } else {
            current_column += 1;
        }
    }

    // Handle the case where byte_range.end is at the end of the string
    if !found_start && byte_range.start == content.len() {
        line_start = current_line;
        column_start = current_column;
    }

    if byte_range.end == content.len() {
        line_end = current_line;
        column_end = current_column;
    }

    (line_start - 1, column_start, line_end - 1, column_end)
}
