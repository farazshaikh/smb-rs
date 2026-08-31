---
name: smb-rs-conventions
description: 'Coding conventions for the smb-rs pure-Rust SMB1/SMB2/SMB3 server workspace. USE WHEN writing, reviewing, or refactoring Rust in this repo — especially: implementing a protocol feature faithfully from the [MS-SMB2]/[MS-CIFS] spec PDFs instead of just making a test pass; documenting public items (the workspace denies `missing_docs`); and replacing hardcoded protocol magic numbers / wire offsets / command codes / NT status values with named constants defined in the `smb-proto*` crates. Triggers: "smb-rs convention", "implement from spec", "reward hacking", "make the test pass", "MS-SMB2 pdf", "missing docs", "why does this compile without docs", "hardcoded constant", "magic number", "magic byte", "0xFE 0xFD 0xFC", "define constant in protocol", "clippy lint for literals", "disallow literals", "adding a command", "code review smb".'
---

# smb-rs conventions

Conventions for the `smb-rs` workspace (a pure-Rust SMB1/2/3 file server). Apply
these when adding or reviewing code. Some are enforced by the compiler; the rest
are enforced by review.

## 1. Implement the protocol from the spec — never just to pass a test

The goal is a correct SMB server, not a green test. When a test fails or a
feature is missing:

- Read the authoritative spec first. The PDFs live in the repo:
  `docs/protocol/smb2_3/MS-SMB2.pdf` (and the SMB1/CIFS docs under
  `docs/protocol/smb1/`). Related specs: [MS-FSA], [MS-FSCC], [MS-DTYP],
  [MS-RPCE], [MS-SRVS], [MS-DFSC].
- Implement the **full behavior** the spec section prescribes — every field,
  status code, ordering rule, and edge case — and cite the section in a comment,
  e.g. `([MS-SMB2] §3.3.5.9)`.
- **Do not reward-hack.** Never special-case a value, hardcode a response the
  test happens to check, skip validation, or fake data (e.g. inventing snapshot
  entries) just to flip a test to pass. If the environment genuinely can't
  support a feature (no domain, no second NIC, no ReFS), say so and leave it
  unimplemented rather than faking it.
- If the spec and a test disagree, trust the spec and note the discrepancy.

A change is "done" when it matches the spec, keeps the regression gate green
(see §4), and adds no shortcut that would mislead a future reader.

## 2. Document every public item (compiler-enforced)

`missing_docs` is denied workspace-wide via `[workspace.lints.rust]` in the root
`Cargo.toml`, and every crate opts in with `[lints]` + `workspace = true`. Any
`pub` / `pub(crate)` item without a `///` doc comment is a **compile error**.

Rules:
- Every public struct, field, enum, variant, function, method, trait, and
  constant gets a `///` doc comment.
- Keep docs informational; state what the code cannot show on its own (the spec
  section, an invariant, a unit). Do not restate the signature.
- Prefer one focused line. Multi-paragraph docs are only for genuinely subtle
  items.

Common failure mode: a doc comment gets **orphaned** onto the wrong item when a
new function is inserted between an existing doc block and its `fn`. After adding
a function, re-check that each `///` block still sits on its intended item.

If undocumented `pub` code ever compiles, that crate is missing its `[lints]` +
`workspace = true` opt-in — add it.

## 3. No hardcoded protocol constants (lint-enforced)

Never write wire-level magic numbers inline — protocol magic bytes, command
codes, NT status values, structure sizes, field offsets, FSCTL codes,
capability/flag bits, dialect numbers. Define a **named constant** in the
protocol crate that owns that wire format and reference it:

| What | Crate / module |
|------|----------------|
| SMB2/3 headers, magics, command codes, FSCTLs, contexts | `smb-proto-smb2` (`lib.rs`, `consts`, `commands`, `session_setup::cmd`) |
| SMB1 headers, command bytes, flags | `smb-proto-smb1` (`consts`) |
| NT status codes, common wire types | `smb-proto` (`types`) |

Example — the dispatch loop used to branch on raw first bytes:

```rust
// BAD — magic numbers inline
if frame.0[0] == 0xFE || frame.0[0] == 0xFD || frame.0[0] == 0xFC { ... }
```

The full 4-byte ProtocolIds already exist as constants
(`smb_proto_smb2::SMB2_MAGIC`, `commands::TF_MAGIC`, `compress::PROTOCOL_ID`), so
the fix is named first-byte discriminators in `smb-proto-smb2`:

```rust
// GOOD — named, self-documenting, single source of truth
if frame.0[0] == PROTO_ID_SMB2
    || frame.0[0] == PROTO_ID_ENCRYPTED
    || frame.0[0] == PROTO_ID_COMPRESSED { ... }
```

When you need a wire value with no constant yet, add the constant (with a `///`
citing the spec section) next to its peers in the owning `smb-proto*` crate, then
use it — don't inline the literal.

### On lints for this rule

No **built-in** Rust or Clippy lint bans magic-number literals (the
`clippy::disallowed_*` family covers types, methods, macros, names, and
script-idents — not literals). So this repo ships its **own** [dylint](https://github.com/trailofbits/dylint)
lint that does enforce it.

- The lint lives in `lints/no_magic_numbers/` (a standalone crate, `exclude`d
  from the workspace) and is wired via `[workspace.metadata.dylint]` in the root
  `Cargo.toml`. Run it with `cargo dylint --all -- --workspace` (or `-- -p
  <crate>`). It flags every integer literal `> 1` except: const contexts,
  macro expansions, `#[test]` functions, and the `smb_proto*` crates (which are
  the sanctioned home for wire constants).
- **The whole workspace is at zero.** Keep it there: a new inline literal is a
  lint error, not a style nit.

Two ways to satisfy the lint — pick by the literal's nature:

1. **Name genuine wire constants** (offsets, command/status/FSCTL codes, masks,
   structure sizes, dialects). Add the constant in the owning `smb-proto*` crate
   (with a `///` citing the spec section) and reference it. This is the default
   and preferred fix. Also prefer `size_of::<uN>()` / `.len()` for field widths
   and reuse existing helpers (e.g. `FileTime::from_unix`) over re-deriving
   constants.
2. **Allow inherent-algorithm domains.** Functions dominated by an intrinsic
   format or math — calendar/FILETIME arithmetic, crypto primitives (DES/MD4/
   KDF/AEAD), ASN.1/DER + SPNEGO parsing, DCERPC/NDR and TRANS2 wire layout,
   POSIX/statfs mapping, base64/JSON escaping, test-fixture sizes — carry a
   function-level attribute **with a rationale comment**:

   ```rust
   #[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // NTLM proof field widths ([MS-NLMP])
   fn derive_session_key(...) { ... }
   ```

   The `unexpected_cfgs` check-cfg in the root `Cargo.toml` makes this attribute
   build warning-free even when dylint isn't running. Do not blanket-allow a
   whole module or reach for the allow when a named constant is the honest fix.


## 4. Build / test gate (review-enforced)

- Use `bash` for all shell commands (never fish).
- After a change: `cargo build -p smb-server` and `cargo test --workspace` must
  be green. Note: `cargo check --all-features` intentionally fails on `smb-csp`
  (its `lib` and `handrolled` backends are mutually exclusive by a
  `compile_error!` guard) — check the backends separately, not with
  `--all-features`.
- Protocol-affecting changes must keep the regression gate: SMB2Basic BVT 27/27,
  the home-grown conformance run 30/30, and the MS-SMB2 protocol sweep count
  unchanged. See `session_summary_*.txt` and the test dashboard for the baseline.
- Keep `cargo dylint --all -- --workspace` at **zero** magic-number findings
  (see §3).
- Commit messages carry **no** model/AI attribution.
