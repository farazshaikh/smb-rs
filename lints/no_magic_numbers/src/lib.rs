#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use clippy_utils::is_in_const_context;
use clippy_utils::is_in_test_function;
use rustc_ast::ast::LitKind;
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::def_id::LOCAL_CRATE;

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// Flags integer literals (other than `0` and `1`) used in expression
    /// position — "magic numbers".
    ///
    /// ### Why is this bad?
    /// In this workspace every wire-level value (protocol magic, command code,
    /// NT status, structure size, field offset, FSCTL code, flag bit, dialect)
    /// must be a named constant defined in the owning `smb-proto*` crate and
    /// referenced by name, so the meaning is self-documenting and lives in one
    /// place. A raw literal in the server logic hides intent and duplicates a
    /// value the protocol layer already names.
    ///
    /// ### Known problems
    /// Only integer literals are checked. Values legitimately defined as
    /// constants (see exceptions) are not flagged.
    ///
    /// ### Example
    /// ```rust,ignore
    /// if frame[0] == 0xFE { /* ... */ }
    /// ```
    /// Use instead:
    /// ```rust,ignore
    /// if frame[0] == PROTO_ID_SMB2 { /* ... */ }
    /// ```
    pub NO_MAGIC_NUMBERS,
    Warn,
    "integer literal that should be a named constant defined in an smb-proto* crate"
}

impl<'tcx> LateLintPass<'tcx> for NoMagicNumbers {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // Literals produced by macro expansion (metrics!, tracing!, format!,
        // derives, …) are not the author's magic numbers — skip them.
        if expr.span.from_expansion() {
            return;
        }
        let ExprKind::Lit(lit) = &expr.kind else {
            return;
        };
        let LitKind::Int(value, _) = lit.node else {
            return;
        };
        // 0 and 1 are structural noise, not magic.
        if value.get() <= 1 {
            return;
        }
        // Constant definitions, array lengths and enum discriminants are exactly
        // where a literal belongs.
        if is_in_const_context(cx) {
            return;
        }
        // Test code is not production wire handling.
        if is_in_test_function(cx.tcx, expr.hir_id) {
            return;
        }
        // The smb-proto* crates DEFINE the wire constants; literals are expected
        // there. Consumer crates must reference the named constants instead.
        if cx
            .tcx
            .crate_name(LOCAL_CRATE)
            .as_str()
            .starts_with("smb_proto")
        {
            return;
        }
        span_lint_and_help(
            cx,
            NO_MAGIC_NUMBERS,
            expr.span,
            "magic number: use a named constant",
            None,
            "define this value as a named constant in the owning smb-proto* crate and reference it by name",
        );
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
