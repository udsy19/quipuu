//! Intra-procedural variable-binding resolution — Program.md M4, stage 1.
//!
//! Direction.md names call-path evidence as the keystone the rest of the
//! product leans on, taken in stages: (1) same-variable-across-statements
//! within one function, (2) receiver-type resolution, (3) module
//! reachability, (4) cross-file paths. This module is stage 1 only.
//!
//! Given a variable-name use inside a function body (e.g. the receiver of
//! `key.sign(...)`, or an argument), [`resolve_local_binding`] finds the
//! nearest preceding assignment of that name within the same function and
//! returns its right-hand-side expression node — so a caller can treat the
//! use site as if the original construction expression had appeared inline,
//! closing the `#Y8`/`#Y47` class where an algorithm is selected on one
//! line and used on the next.
//!
//! Scope, stated rather than assumed: only Python and JavaScript/TypeScript
//! are covered. Search is block-local and walks outward one enclosing block
//! at a time, most recent binding first — it does not model control flow
//! (an assignment inside a conditional branch is treated the same as one on
//! the fall-through path), shadowing across nested scopes beyond the
//! immediate walk, or reassignment after the use site. Those are honest
//! gaps in a stage-1 primitive, not bugs to route around silently: a caller
//! that needs a stronger guarantee should not rely on this alone.
//!
//! Not yet wired into any `[[extract]]`/`[[classify]]` rule or the `walk`
//! dispatch — landing as a standalone, tested primitive per the Program's
//! "a capability may land unfinished" rule. Detection output is therefore
//! unchanged by this file's presence.

use tree_sitter::Node;

use crate::rules::Language;

/// Node kinds that scope a variable binding — the boundary the backward
/// search stops widening past. Matches the granularity `walk`'s own
/// function-boundary checks already use elsewhere in this crate.
fn is_function_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition"
            | "function_declaration"
            | "method_declaration"
            | "arrow_function"
            | "function"
    )
}

/// Find the nearest preceding binding of `name` among the statement-level
/// children of `block`, searching backward from (but not including) the
/// statement at or after `before_byte`. Returns the bound expression.
fn find_binding_in_block<'a>(
    block: Node<'a>,
    name: &str,
    before_byte: usize,
    source: &[u8],
    language: Language,
) -> Option<Node<'a>> {
    let mut cursor = block.walk();
    let candidates: Vec<Node<'a>> = block
        .children(&mut cursor)
        .filter(|c| c.start_byte() < before_byte)
        .collect();
    for stmt in candidates.into_iter().rev() {
        if let Some(value) = binding_target(stmt, name, source, language) {
            return Some(value);
        }
    }
    None
}

/// If `stmt` binds `name` directly (an assignment or a declarator naming
/// it), return the value expression it binds it to.
fn binding_target<'a>(
    stmt: Node<'a>,
    name: &str,
    source: &[u8],
    language: Language,
) -> Option<Node<'a>> {
    match language {
        Language::Python => python_binding_target(stmt, name, source),
        Language::JavaScript | Language::TypeScript => js_binding_target(stmt, name, source),
        _ => None,
    }
}

/// Python: `expression_statement` wrapping an `assignment` whose `left` is
/// the plain identifier `name`; `right` is the bound value.
fn python_binding_target<'a>(stmt: Node<'a>, name: &str, source: &[u8]) -> Option<Node<'a>> {
    let assignment = if stmt.kind() == "expression_statement" {
        stmt.child(0)?
    } else {
        stmt
    };
    if assignment.kind() != "assignment" {
        return None;
    }
    let left = assignment.child_by_field_name("left")?;
    if left.kind() != "identifier" || node_text(left, source) != name {
        return None;
    }
    assignment.child_by_field_name("right")
}

/// JS/TS: either a `lexical_declaration`/`variable_declaration` containing a
/// `variable_declarator` naming `name`, or an `expression_statement`
/// wrapping an `assignment_expression` whose `left` is `name`.
fn js_binding_target<'a>(stmt: Node<'a>, name: &str, source: &[u8]) -> Option<Node<'a>> {
    match stmt.kind() {
        "lexical_declaration" | "variable_declaration" => {
            let mut cursor = stmt.walk();
            stmt.children(&mut cursor)
                .filter(|c| c.kind() == "variable_declarator")
                .find_map(|decl| {
                    let id = decl.child_by_field_name("name")?;
                    if id.kind() == "identifier" && node_text(id, source) == name {
                        decl.child_by_field_name("value")
                    } else {
                        None
                    }
                })
        }
        "expression_statement" => {
            let expr = stmt.child(0)?;
            if expr.kind() != "assignment_expression" {
                return None;
            }
            let left = expr.child_by_field_name("left")?;
            if left.kind() == "identifier" && node_text(left, source) == name {
                expr.child_by_field_name("right")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Resolve `identifier`'s nearest preceding intra-procedural binding.
///
/// Walks from `identifier` up through enclosing blocks (most recent binding
/// in the innermost block wins), stopping at the first function-shaped
/// boundary — a binding outside the enclosing function is out of scope for
/// this stage, per Direction.md's stage split (module-level reachability is
/// stage 3). Returns `None` if `identifier` is not a plain name, no binding
/// is found before it, or the language is not one of the two covered here.
pub fn resolve_local_binding<'a>(
    identifier: Node<'a>,
    source: &[u8],
    language: Language,
) -> Option<Node<'a>> {
    if identifier.kind() != "identifier" {
        return None;
    }
    let name = node_text(identifier, source);
    let use_byte = identifier.start_byte();
    let mut block = identifier.parent();
    while let Some(b) = block {
        if matches!(b.kind(), "block" | "statement_block") {
            if let Some(found) = find_binding_in_block(b, &name, use_byte, source, language) {
                return Some(found);
            }
        }
        if is_function_boundary(b.kind()) {
            break;
        }
        block = b.parent();
    }
    None
}

fn node_text(node: Node<'_>, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn find_identifier_use<'a>(root: Node<'a>, source: &[u8], name: &str, nth: usize) -> Node<'a> {
        let mut found = Vec::new();
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if n.kind() == "identifier" && node_text(n, source) == name {
                found.push(n);
            }
            let mut cursor = n.walk();
            for child in n.children(&mut cursor) {
                stack.push(child);
            }
        }
        found.sort_by_key(|n| n.start_byte());
        found[nth]
    }

    #[test]
    fn python_resolves_binding_set_one_line_and_used_the_next() {
        let source = b"def make():\n    key = RSA.generate(2048)\n    key.sign(msg)\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        // second occurrence of `key` is the receiver at `key.sign(msg)`.
        let use_site = find_identifier_use(tree.root_node(), source, "key", 1);
        let resolved = resolve_local_binding(use_site, source, Language::Python)
            .expect("binding should resolve");
        assert_eq!(resolved.utf8_text(source).unwrap(), "RSA.generate(2048)");
    }

    #[test]
    fn python_last_write_wins() {
        let source = b"def make():\n    algo = 'md5'\n    algo = 'sha256'\n    hashlib.new(algo)\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let use_site = find_identifier_use(tree.root_node(), source, "algo", 2);
        let resolved = resolve_local_binding(use_site, source, Language::Python).unwrap();
        assert_eq!(resolved.utf8_text(source).unwrap(), "'sha256'");
    }

    #[test]
    fn python_binding_outside_the_function_does_not_resolve() {
        let source = b"key = RSA.generate(2048)\n\ndef use():\n    key.sign(msg)\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let use_site = find_identifier_use(tree.root_node(), source, "key", 1);
        assert!(resolve_local_binding(use_site, source, Language::Python).is_none());
    }

    #[test]
    fn javascript_resolves_const_declarator() {
        let source = b"function make() {\n  const key = crypto.createSign('RSA-SHA256');\n  key.update(data);\n}\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let use_site = find_identifier_use(tree.root_node(), source, "key", 1);
        let resolved = resolve_local_binding(use_site, source, Language::JavaScript).unwrap();
        assert_eq!(
            resolved.utf8_text(source).unwrap(),
            "crypto.createSign('RSA-SHA256')"
        );
    }

    #[test]
    fn javascript_resolves_plain_assignment() {
        let source =
            b"function make() {\n  let algo;\n  algo = 'aes-256-gcm';\n  cipher(algo);\n}\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let use_site = find_identifier_use(tree.root_node(), source, "algo", 2);
        let resolved = resolve_local_binding(use_site, source, Language::JavaScript).unwrap();
        assert_eq!(resolved.utf8_text(source).unwrap(), "'aes-256-gcm'");
    }

    #[test]
    fn unsupported_language_returns_none() {
        let source = b"func make() {\n\tkey := rsa.GenerateKey()\n\tkey.Sign()\n}\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let use_site = find_identifier_use(tree.root_node(), source, "key", 1);
        assert!(resolve_local_binding(use_site, source, Language::Go).is_none());
    }
}
