# Typestate Plan: an SMB request/response state machine encoded in the type system

Status: proposal. Target crate(s): `smb-server` (new `io` module), with small
additions to `smb-proto-smb2`. This plan is **incremental and non-breaking**: the
current dispatcher (`dispatch::serve_client` → `smb2::process_frame` →
`process_single`) keeps working and the regression gate (SMB2Basic BVT 27/27 +
`cargo test --workspace` + smbprotocol conformance 30/30) must stay green after
every phase.

## 1. Why typestate

Aldrich, Sunshine, Saini & Sparks, *Typestate-Oriented Programming* (Onward!
2009), make a program's **state part of its type**: an object is an instance of
one *state*, each state exposes only the operations that are legal in it, and a
transition **consumes** the old state to yield the new one. Illegal sequences
(reading a closed file, responding twice, completing a request that was never
accepted) become **compile errors** instead of runtime bugs.

Rust has no first-class typestate, but it has the two ingredients the paper
relies on:

- **Affine/linear ownership** — a value moved into a transition cannot be used
  again, so "the request was consumed to build the context" is enforced by the
  borrow checker.
- **Zero-cost state markers** — a generic `Ctx<State>` plus a *sealed* marker
  trait models "the same object in different states" with no runtime overhead.

Today the lifecycle is untyped: `process_single` returns `Option<(Vec<u8>,
bool)>` — a raw byte blob plus a "may-encrypt" flag — and every command matches a
big `enum`, hand-builds a header via `response(...)`, and there is no type-level
distinction between *accepted*, *pending* (STATUS_PENDING), *completed*, and
*unsolicited* (oplock/lease break) work. The states exist only in the
programmer's head and in comments.

## 2. The pipeline as a chain of types

```mermaid
stateDiagram-v2
    [*] --> WireBytes: transport.recv()
    WireBytes --> FrameStream: length-prefix framing
    FrameStream --> SmbRequest: Decode (per-command)
    SmbRequest --> IoContext_Accepted: IoContext::accept(req)  (consumes req)
    IoContext_Accepted --> SmbResponse_Final: serve() -> Final   (consumes ctx)
    IoContext_Accepted --> IoContext_Pending: serve() -> Interim (returns ctx + interim resp)
    IoContext_Pending --> SmbResponse_Final: complete(result)    (consumes ctx)
    SmbResponse_Final --> [*]: encode() -> bytes -> writer

    ServerEvent --> IoContext_Unsolicited: from_event()  (no SmbRequest)
    IoContext_Unsolicited --> SmbResponse_Final: into_response()
```

The six stages the design must express (verbatim from the request), mapped to
concrete types:

| # | Stage | Type | Ownership rule |
|---|-------|------|----------------|
| 1 | read wire → streamable buffer | `FrameStream<R: FrameSource>` yielding `RawFrame` | borrows the read half |
| 2 | buffer → request sum type | `SmbRequest` (enum of every handled command) | owns parsed body + `Header2` |
| 3 | request → server work item | `IoContext<Accepted>` | **consumes** `SmbRequest` |
| 4 | serve the work item | `impl` over `IoContext<S>` behind the `Command`/`Serve` traits | owns the request for its whole life |
| 5 | work item → response | `SmbResponse` via `serve`/`complete` | **consumes** ctx (final) or **returns** ctx (interim) |
| 6 | unsolicited response | `IoContext<Ready, Unsolicited>` | no `SmbRequest`, built from a server event |

## 3. States and origins as marker traits

Two orthogonal dimensions. **Lifecycle state** (where in processing we are) and
**origin** (was this triggered by a client request or by the server).

```rust
mod state {
    /// Sealed so only this crate defines lifecycle states.
    mod sealed { pub trait Sealed {} }

    /// A lifecycle state of an [`IoContext`].
    pub trait IoState: sealed::Sealed {}

    /// Parsed, bound to a session/tree, accepted for processing, no reply yet.
    pub enum Accepted {}
    /// An interim STATUS_PENDING reply was sent; the final reply is owed.
    pub enum Pending {}
    /// A final response has been produced; the context is spent.
    pub enum Completed {}

    impl sealed::Sealed for Accepted {}
    impl sealed::Sealed for Pending {}
    impl sealed::Sealed for Completed {}
    impl IoState for Accepted {}
    impl IoState for Pending {}
    impl IoState for Completed {}
}

mod origin {
    mod sealed { pub trait Sealed {} }

    /// Where an [`IoContext`] came from. Determines whether it carries a request
    /// and whether responses echo a client header.
    pub trait Origin: sealed::Sealed {
        /// The owned request payload (`()` for unsolicited).
        type Request;
    }

    /// Triggered by a client frame; owns the parsed [`SmbRequest`] and echoes
    /// its MessageId/SessionId/TreeId.
    pub struct Solicited(pub crate::io::SmbRequest);
    /// Triggered by a server event (oplock/lease break, CHANGE_NOTIFY cleanup);
    /// no request, header fields are server-chosen (e.g. SessionId = 0 for a
    /// lease break, [MS-SMB2] §3.3.4.6).
    pub struct Unsolicited;

    impl sealed::Sealed for Solicited {}
    impl sealed::Sealed for Unsolicited {}
    impl Origin for Solicited { type Request = crate::io::SmbRequest; }
    impl Origin for Unsolicited { type Request = (); }
}
```

`IoContext` is generic over both, but 99% of code names only the pair it needs:

```rust
pub struct IoContext<S: IoState, O: Origin = Solicited> {
    conn: ConnRef,          // per-connection state (handles, session, credits…)
    shared: Arc<ServerShared>,
    binding: Binding,       // resolved session + tree (or "pre-session")
    origin: O,              // owns the SmbRequest when Solicited
    reply_hdr: ReplyHeader, // MessageId, async id, signing/encryption intent
    _state: PhantomData<S>,
}
```

## 4. Stage 1–2: wire → `SmbRequest`

Framing stays behind the existing `FrameSource`; we wrap it so the reader is a
typed stream of *validated* frames rather than raw `Vec<u8>`:

```rust
pub struct RawFrame(Frame);           // exactly one \xFESMB frame (invariant)
pub struct FrameStream<R: FrameSource> { src: R }

impl<R: FrameSource> FrameStream<R> {
    pub async fn next(&mut self) -> Result<Option<RawFrame>, TransportError>;
}
```

Decoding is generalized by a trait, one impl per command. `SmbRequest` is the
sum type over everything the server handles:

```rust
/// Decode a command body once its header says which command it is.
pub trait Decode: Sized {
    const COMMAND: u16;                 // ss::cmd::* value
    fn decode(hdr: &Header2, body: &[u8]) -> Result<Self, Status>;
}

pub enum SmbRequest {
    Negotiate(NegotiateReq),
    SessionSetup(SessionSetupReq),
    TreeConnect(TreeConnectReq),
    Create(CreateReq),                  // already exists in smb-proto-smb2
    Read(ReadReq),  Write(WriteReq),  Close(CloseReq),
    Ioctl(IoctlReq), Lock(LockReq), QueryDir(QueryDirReq),
    QueryInfo(QueryInfoReq), SetInfo(SetInfoReq),
    ChangeNotify(ChangeNotifyReq), Flush(FlushReq),
    Echo, Cancel(CancelReq), Logoff, TreeDisconnect,
    OplockBreakAck(OplockBreakAck), LeaseBreakAck(LeaseBreakAck),
}

impl SmbRequest {
    /// Header (already parsed) + body → the typed request, or an error status to
    /// return without a body.
    pub fn parse(hdr: &Header2, body: &[u8]) -> Result<SmbRequest, Status>;
    pub fn command(&self) -> u16;
    pub fn header(&self) -> &Header2;   // MessageId/flags echoed on reply
}
```

Compound chains ([MS-SMB2] §3.3.5.2.7) are a `Vec<SmbRequest>` produced by the
frame walker; the related-request wildcard-FileId substitution that
`process_frame` does today becomes a pass over that vector before `accept`.

## 5. Stage 3–5: `IoContext` and the `Command` trait

`accept` is the linear hand-off: the `SmbRequest` is **moved** into the context
and cannot be touched again except through it.

```rust
impl IoContext<Accepted, Solicited> {
    pub fn accept(shared: Arc<ServerShared>, conn: ConnRef, req: SmbRequest)
        -> Result<Self, Rejected>;      // resolves session/tree binding
    pub fn request(&self) -> &SmbRequest { &self.origin.0 } // borrow, never move out
}
```

The bulk of the server becomes handlers behind one trait. Each command owns its
request for the whole handler; the handler decides the *outcome*, which encodes
the final-vs-interim distinction in the type system:

```rust
/// The result of serving one accepted request.
pub enum Outcome {
    /// Terminal reply; the context is consumed.
    Final(SmbResponse),
    /// Interim STATUS_PENDING reply now, final reply owed later. The context is
    /// handed back in the Pending state and parked ([MS-SMB2] §3.3.4.2).
    Interim { parked: IoContext<Pending, Solicited>, interim: SmbResponse },
    /// No reply at all (e.g. CANCEL of an unknown id, or a connection-terminating
    /// downgrade check that also sets `disconnect`).
    Silent,
}

/// One command's server-side behaviour. Generalizes the giant match: a command
/// is any type mapping its `Request` to an `Outcome`.
#[async_trait(?Send)]
pub trait Command {
    type Request: Decode;
    async fn serve(ctx: IoContext<Accepted, Solicited>, req: Self::Request)
        -> Outcome;
}
```

Dispatch is then a thin, exhaustive match that *moves* the request out of the
context into the matching `Command::serve` — the only place the sum type is
destructured:

```rust
pub async fn serve(ctx: IoContext<Accepted>) -> Outcome {
    match ctx.take_request() {           // consumes origin, returns (ctx, SmbRequest)
        (ctx, SmbRequest::Echo)         => EchoCmd::serve(ctx, ()).await,
        (ctx, SmbRequest::Create(r))    => CreateCmd::serve(ctx, r).await,
        (ctx, SmbRequest::Lock(r))      => LockCmd::serve(ctx, r).await,
        // …one arm per command…
    }
}
```

Building the reply is stage 5. `SmbResponse` is a typed payload plus the header
intent; it knows how to serialize itself, replacing the ad-hoc `response(...)`
helper:

```rust
pub struct SmbResponse { status: Status, body: Vec<u8>, seal: SealIntent }

/// Serialize a typed response body against a reply header.
pub trait Encode { fn encode(&self, hdr: &ReplyHeader) -> Vec<u8>; }

impl IoContext<Completed, Solicited> {          // reached only via Outcome::Final
    pub fn into_response(self) -> SmbResponse;  // consumes ctx
}

impl IoContext<Pending, Solicited> {
    /// The async worker calls this when the deferred op finishes; it consumes
    /// the parked context and yields the final frame.
    pub fn complete(self, result: OpResult) -> SmbResponse;
}
```

Why this is better than `Option<(Vec<u8>, bool)>`:

- `Interim` **must** return a `Pending` context — you cannot send an interim
  reply and forget to park the work; the type won't let you drop it silently.
- `complete` is only callable on `IoContext<Pending>`, so you cannot double-reply
  to an already-`Final` request.
- The `bool` "may-encrypt" flag becomes `SealIntent` carried in the header,
  computed once at `accept` from the session/request, not threaded by hand.

## 6. Stage 6: unsolicited responses

Oplock breaks, lease breaks, and CHANGE_NOTIFY cleanups have **no** originating
frame. Today they are built by `send_lease_break` / `send_oplock_break` /
`build_break_frame` and pushed onto `out_tx` directly, with the SessionId=0
subtlety ([MS-SMB2] §3.3.4.6) hand-coded. In the typestate model they are just
an `IoContext` with the `Unsolicited` origin, so they share the same
`SmbResponse`/`Encode`/sealing path:

```rust
impl IoContext<Ready, Unsolicited> {
    /// Build from a server event; there is no request and no session echo.
    pub fn from_event(shared: Arc<ServerShared>, ev: ServerEvent) -> Self;
    pub fn into_response(self) -> SmbResponse;  // e.g. LEASE_BREAK notification
}

pub enum ServerEvent {
    LeaseBreak  { key: [u8;16], from: u32, to: u32, epoch: u16, seal: SealIntent },
    OplockBreak { file_id: [u8;16], level: u8, seal: SealIntent },
    NotifyCleanup { file_id: [u8;16], async_id: u64 },
}
```

The writer task keeps draining one `mpsc::Sender<SmbResponse>` (was
`Sender<Vec<u8>>`); solicited and unsolicited responses converge on the same
queue after `encode()`, so signing/sealing lives in exactly one place.

## 7. Trait summary (the generalization the request asks for)

| Trait | Role | Replaces |
|-------|------|----------|
| `Decode` | wire body → typed request (per command) | inline `*::parse` calls in the match |
| `Encode` | typed response → bytes | scattered `build_*_resp` + `response()` |
| `IoState` (sealed) | lifecycle marker: `Accepted`/`Pending`/`Completed` | comments & discipline |
| `Origin` (sealed) | `Solicited` (owns request) vs `Unsolicited` | two separate code paths |
| `Command` | one command's `Request → Outcome` handler | arms of the big `match` |
| `Encode`/`SealIntent` | one signing/sealing site | the `bool` may-wrap flag |

## 8. Incremental migration (keep every phase green)

Ground truth to preserve: `dispatch::serve_client` is the live loop
(`main.rs:152`), `process_single` returns `Option<(Vec<u8>, bool)>`, unsolicited
frames go through `conn.outbound`. Each phase ends with BVT 27/27 + workspace +
conformance 30/30 and a commit.

- **Phase 0 — scaffolding.** [DONE] New `smb-server/src/io/` module with the
  marker traits, `IoState`, `Origin`, `SmbResponse`, `ReplyHeader`, `SealIntent`.
- **Phase 1 — `Decode` + `SmbRequest`.** [DONE] `Decode` for the data-plane
  request structs + `SmbRequest::parse`, generated by `smb_request_table!`.
- **Phase 2 — `IoContext` for leaf commands.** [DONE] `ECHO` wired end to end
  through `accept → serve → respond`.
- **Phase 3 — migrate command clusters.** [DONE] `FLUSH`, `TREE_DISCONNECT`,
  `LOGOFF`, then `READ`/`WRITE`, `CLOSE`, `QUERY_DIRECTORY`/`QUERY_INFO`/
  `SET_INFO`, `IOCTL`, and `CREATE` moved into `Command` impls. Intricate bodies
  (create/close/ioctl) stayed as `pub(crate)` functions in `smb2.rs` that the
  thin handlers call, keeping all private helpers in one module.
- **Phase 4 — `Pending`.** [DONE] `LOCK` waits and `CHANGE_NOTIFY` model
  STATUS_PENDING with `Outcome::Interim` + `IoContext<Pending>`; `via_typestate`
  frames the async interim from the parked context (`build_async_frame` + sign)
  and returns `Routed::Raw`. `CANCEL` returns `Outcome::Silent`. The background
  `run_lock_wait`/`run_change_notify` workers still send the final reply on
  `conn.outbound`. `OPLOCK_BREAK` acks migrated too.
- **Phase 6 — retire the old per-command dispatch.** [DONE] `TREE_CONNECT`
  (via `conn.resp_tree_id`), `SESSION_SETUP` and `NEGOTIATE` migrated. Every SMB2
  command the server answers now dispatches through the typestate pipeline;
  `process_single`'s `match` only routes each code to `route!()` plus a
  `NOT_IMPLEMENTED` catch-all. The trailing common stage is pure framing/crypto
  (pre-auth hash, session registration, signing-key derivation, sealing) shared
  by every command — the deliberate single serialization/crypto site.
- **Phase 5 — `Unsolicited`.** [DEFERRED, by design] `send_lease_break` /
  `send_oplock_break` remain on the dedicated server-event seam: they are
  fire-and-forget notifications built by `build_break_frame` (MessageId all-ones,
  SessionId 0) and sealed with a `BreakCrypto` snapshot, emitted from the lease/
  oplock managers rather than the request loop. The typestate's core guarantee —
  enforcing the *request* lifecycle (accept→serve→respond, defer→complete) in the
  type system — does not apply to these events, and §12/§13 already name the
  transport/event boundary as the one imperative seam. The `Unsolicited` origin
  and `from_event` remain as the typed model for a future unification of all
  three frame shapes (solicited `response`, async `build_async_frame`, break
  `build_break_frame`) behind one `SmbResponse` serializer — a structural
  refinement that would touch every frame's exact bytes and is intentionally not
  bundled with the behavior-preserving command migration.

### Achieved end state

All 17 answered command codes (NEGOTIATE, SESSION_SETUP, TREE_CONNECT,
TREE_DISCONNECT, LOGOFF, CREATE, CLOSE, READ, WRITE, FLUSH, LOCK, IOCTL, CANCEL,
ECHO, QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, SET_INFO, OPLOCK_BREAK) are
`Command` impls dispatched by the generated static `match`. `via_typestate`
returns `Routed { Framed(status, body) | Raw(frame) | Silent }`; `process_single`
routes with a `route!()` macro and applies the shared framing/crypto tail. No
regression across the migration: BVT 27/27, conformance 30/30, MS-SMB2 protocol
sweep 118/286 unchanged at every phase.



## 9. Notes and constraints

- **`!Send`, single thread.** All futures are `#[async_trait(?Send)]` on one
  `tokio_uring` runtime, so `IoContext` may hold `!Send` handles
  (`tokio_uring::fs::File`) and be moved across `.await` freely — no `Arc<Mutex>`
  needed for per-connection state.
- **No behavior change is a feature.** The typestate refactor must not move any
  test from pass→fail; it is a structural change validated by the existing
  suites, not a functional one.
- **Sealed traits** keep `IoState`/`Origin` closed so downstream code can't add
  illegal states, matching the paper's closed-state-set model.
- **Zero cost.** `PhantomData<S>` markers and moved-by-value transitions compile
  to the same code as today; the win is that illegal lifecycles stop compiling.

## 10. Proven Rust idioms this design leans on

Sources: Cliffle, *The Typestate Pattern in Rust* (cliffle.com/blog/rust-typestate);
the Embedded Rust Book, *Typestate Programming*; Crichton, *Type-Driven API Design*.
The pattern is idiomatic Rust — `std::fs::File` (open/closed via move-on-`drop`),
the builder pattern (`FooBuilder::into_foo(self) -> Foo`), and `serde`'s
`Serializer`/`SerializeStruct` are all typestate machines. Three techniques from
that literature shape our choices:

1. **State as a type parameter, not just separate structs.** A single
   `IoContext<S, O>` with per-state `impl` blocks keeps all operations on one
   rustdoc page under separate headings, and lets us write cross-state helpers by
   leaving `S` unconstrained (`impl<S: IoState> IoContext<S> { fn message_id(&self) }`)
   or bounding a subset via a marker trait (`impl<S: Replyable> IoContext<S>`).
   This is exactly the article's "state type parameter" variation.

2. **State types that *carry* their data** (the article's last variation).
   Rather than `PhantomData<S>` plus `Option<...>` fields that are only valid in
   some states, put the data *in* the state so it cannot be accessed in the wrong
   state and costs nothing in the others:

   ```rust
   pub struct Accepted;                        // no extra data
   pub struct Pending {                         // only exists while parked
       async_id: u64,
       cancel: oneshot::Receiver<Status>,       // unreachable from Accepted/Completed
   }
   struct IoContext<S, O: Origin> { shared: Arc<ServerShared>, conn: ConnRef,
                                    reply_hdr: ReplyHeader, origin: O, state: S }
   ```

   So `cancel`/`async_id` are simply *not present* on an `IoContext<Accepted>` —
   you cannot complete a request that was never deferred, and there is no `None`
   to unwrap. `Solicited(SmbRequest)` / `Unsolicited` follow the same rule for the
   request payload.

3. **`self`-consuming transitions, `&mut self` for in-state work.** Every state
   *change* takes `self` by value so the prior state becomes unusable (the whole
   point). Operations that don't change state — credit accounting, appending a
   compound frame, reading the request — take `&self`/`&mut self` so we avoid the
   awkward `ctx = ctx.step()` reassignment the article warns about, e.g. inside
   the compound loop.

## 11. Pitfalls to plan around

- **`async_trait` erases lifetimes, not state.** `Command::serve` is fine as
  `#[async_trait(?Send)]`, but a `dyn Command` **object** cannot carry the
  `IoContext<Accepted>` in its signature and stay object-safe with the state
  param. Keep dispatch as a concrete `match` (Section 5) that calls monomorphic
  `Cmd::serve`; do **not** box commands as trait objects keyed by state.
- **`PhantomData` variance.** If we use `PhantomData<S>` markers, prefer
  `PhantomData<fn() -> S>` so the marker is covariant and never adds auto-trait
  obligations; with state-carrying structs (Section 10.2) this is moot.
- **Sealed everything.** `IoState` and `Origin` are sealed so no downstream (or
  accidental in-crate) type can instantiate an illegal state — the closed
  state-set the paper assumes.
- **One serialization site.** All `SmbResponse`s (solicited, interim, unsolicited)
  must flow through a single `encode()` so signing (`sign_pdu`) and sealing
  (`seal_pdu`) — today duplicated between `response()`/`finalize_break`/
  `finalize_async` — happen in exactly one place. This is the concrete bug-class
  the refactor removes (e.g. the SessionId=0 unsigned lease-break rule lives once).
- **Don't regress the wire.** The typestate types are a *re-encoding* of the
  existing behavior. Every phase is gated by SMB2Basic BVT 27/27 + workspace +
  conformance 30/30; a phase that flips any test is reverted, not patched.

## 12. Static vs dynamic dispatch (evaluation of the "prefer generics" ask)

Default is **static dispatch**; the design is static-dominant by construction —
the state/origin dimensions are *type parameters* (no dispatch at all), and the
decode/serve/encode path is concrete `match` + monomorphic calls. Dynamic
dispatch is used at exactly **one** seam — the transport — and that is an
engineering choice, not a fallback from unwieldiness.

| Abstraction | Mechanism | Dispatch | Why |
|---|---|---|---|
| `IoState`, `Origin` | `IoContext<S, O>` type params + state-carrying structs | **none** (monomorphized) | markers/data, not calls — zero cost, `PhantomData`/moved by value |
| `Decode` (req parse) | concrete `match` on command byte → `CreateReq::decode(..)` | **static** | closed command set; each arm is a monomorphic call, inlinable |
| `Command::serve` | concrete `match` on `SmbRequest` → `CreateCmd::serve(..)` | **static** | closed command set; also *required* — a `dyn Command` isn't object-safe with the `IoContext<S>` state param or the assoc. `Request` type |
| `Encode` (resp build) | concrete `SmbResponse` + monomorphic `encode` | **static** | one serialization site, inlinable, no vtable |
| `Outcome`, `ServerEvent` | enums matched concretely | **static** | sum types, not polymorphism |
| `FrameStream<R: FrameSource>` | generic over the reader | **static wrapper** | monomorphic framing; the `R` it holds may itself be a boxed half (below) |
| `Transport` / `FrameSource` / `FrameSink` | `Box<dyn …>` at the I/O edge | **dynamic** | see rationale |

### Why the transport stays `dyn` (and only it)

1. **Heterogeneous impls behind one accept loop.** TCP-over-io_uring today, the
   in-memory test transport, and plausibly QUIC/RDMA later. The accept loop and
   the per-connection writer task store *whichever* transport connected; a
   trait object is the natural fit and keeps `Transport` object-safe.
2. **Cost is noise.** One vtable indirection per `recv`/`send` sits behind a
   syscall and a full frame parse/handle — nanoseconds against microseconds. It
   is never on a hot inner loop.
3. **Generic here would bloat, not speed up.** Making `serve_client<T:
   Transport>` monomorphizes the *entire* per-connection dispatch stack (every
   command handler) once per transport type. That is real code bloat for zero
   measurable win, and it forces `split()` to expose associated `Reader`/`Writer`
   types, making `Transport` no longer object-safe and pushing genericity up
   into the accept loop and tests. Classic "few impls at an I/O boundary → keep
   `dyn`."

So the boundary is: **`dyn` at and below `FrameSource`/`FrameSink`; static
everything above it** (decode → `IoContext` → `Command` → `SmbResponse`). The
generic `FrameStream<R>` bridges them — it is monomorphic but is instantiated
with `R = Box<dyn FrameSource>`, so the dynamic edge is contained to the reader
itself and never leaks into request/response processing.

### Guardrails to keep it static
- No command registry: never `Vec<Box<dyn Command>>` or `HashMap<u16, Box<dyn
  Command>>` — dispatch is the concrete `match` in Section 5.
- Never box an `IoContext`; move it by value through the states.
- Keep spawned async handlers concrete (named futures), not `Box<dyn Future>`.
- **Prefer native `async fn` in traits (Rust ≥ 1.75) for `Command`/`Decode`.**
  Because these are dispatched by concrete `match` (never as trait objects),
  they don't need object safety, so they can use native `async fn` and avoid the
  `Pin<Box<dyn Future>>` that `#[async_trait]` allocates on every call. Keep
  `#[async_trait(?Send)]` only on the traits that *are* used as objects —
  `Transport`/`FrameSource`/`FrameSink` and `Vfs` (`Arc<dyn Vfs>`) — where RPITIT
  object safety doesn't yet apply. This is the fully-static async path.
- If a future refactor ever *does* need a command trait object (e.g. a plugin
  surface), erase state at the boundary only: `dyn Fn(IoContext<Accepted>) ->
  BoxFuture<Outcome>` behind one indirection — and measure before adopting it.

## 13. Performance is non-negotiable

This refactor is a **structural re-encoding with zero runtime cost**. It must not
make anything synchronous, slower, or more allocation-heavy than today. Hard
rules, enforced per phase:

- **Never block the reactor.** Single-threaded `tokio_uring`, all futures
  `?Send`. No `std::thread::sleep`, no synchronous/`blocking_*` I/O, no
  `Mutex` held across `.await`, no busy-waits. STATUS_PENDING work stays a
  spawned async task (Section 6/Phase 4): the `IoContext<Pending>` is **moved
  into** that task and the reader loop is never stalled.
- **One allocation per frame, moved not copied.** The transport already
  allocates a `Vec<u8>` in `recv()`. `RawFrame` **owns that same buffer** and it
  is *moved* into `IoContext` — "IoContext owns the request" means it owns the
  already-allocated frame, **not** a copy. `SmbRequest` holds parsed scalars plus
  **offset ranges** into that owned buffer (not `&[u8]` borrows — which would make
  `IoContext` self-referential — and not copies). Payloads (WRITE data, IOCTL
  input, query buffers) are read by slicing `frame[range]`; the write path stays
  zero-copy end to end.
- **Transitions are moves = free.** State changes take `self` by value and
  return the next type; state-carrying structs (Section 10.2) avoid `Option`
  fields and re-initialization. **Never box an `IoContext`.** `PhantomData`
  markers, if used, are `PhantomData<fn() -> S>` (no size, no drop glue).
- **Static dispatch above the transport** (Section 12) so every handler inlines;
  **native `async fn` in traits** for `Command`/`Decode` so there is no
  per-call `Pin<Box<dyn Future>>`. The lone `dyn` seam (transport) is behind a
  syscall and off every hot inner loop.
- **No new locks, no added contention.** Per-connection state (`IoContext`,
  handle table, credits) is owned by the single connection task and touched
  without synchronization. Shared tables keep their current locking granularity
  (`Arc<Mutex<…>>` per table); the refactor adds none and shortens no critical
  section into a hot loop.
- **Build the reply once.** A response is serialized into one `Vec<u8>` and
  signed/sealed **in place, single pass** (one `encode()` site, Section 5/11) —
  no intermediate structs re-serialized, no double buffering. Signing/sealing is
  computed only when the session negotiated it; plaintext frames never pay for
  crypto they don't use.
- **Compound chains stream.** The chain is walked once; each `IoContext` is
  processed and its reply appended to the outgoing buffer in place (the existing
  8-byte-aligned `NextCommand` fixup), not collected-then-re-copied.
- **Encryption/compression stay opt-in.** Sealing and LZ77 only run when
  negotiated and worthwhile (the current `resp.len() > 1024` gate), never
  unconditionally.

### Guarding it
Correctness gate (BVT 27/27 + workspace + conformance 30/30) is joined by a
**performance gate**: a criterion micro-benchmark over the in-memory transport
measuring (a) frames/sec for a CREATE→WRITE→READ→CLOSE loop and (b) p50/p99
per-frame latency. A phase that regresses either, or that adds a per-frame
allocation shown by a counting allocator in the bench, is **reverted, not
merged** — same discipline as a failing test. Because transitions are moves and
dispatch is static, the expected delta is **zero**; the bench exists to prove it
stayed zero.

## 14. Macro-generated boilerplate

The repetitive part of this design is the **command wiring**: adding one command
today would touch the `SmbRequest` enum, `SmbRequest::parse`,
`SmbRequest::command()`, a `Decode` impl, and the dispatch `match` — five places
that must stay in lock-step. That is exactly what a declarative macro should own,
so the **command table is the single source of truth** and "forgot to add the
arm" becomes impossible.

```rust
macro_rules! smb_commands {
    ( $( $variant:ident = $code:path => $req:ty , $handler:ty ; )* ) => {
        /// Every client request the server decodes (generated from the table).
        pub enum SmbRequest { $( $variant($req), )* }

        impl SmbRequest {
            #[inline]
            pub fn command(&self) -> u16 {
                match self { $( SmbRequest::$variant(_) => $code, )* }
            }
            pub fn parse(hdr: &Header2, body: &[u8]) -> Result<SmbRequest, Status> {
                match hdr.command {
                    $( $code => <$req as Decode>::decode(hdr, body)
                                    .map(SmbRequest::$variant), )*
                    _ => Err(Status::NOT_IMPLEMENTED),
                }
            }
        }

        /// Concrete, static dispatch — one monomorphic call per command.
        pub async fn serve(ctx: IoContext<Accepted>) -> Outcome {
            let (ctx, req) = ctx.take_request();
            match req { $( SmbRequest::$variant(r) => <$handler>::serve(ctx, r).await, )* }
        }
    };
}

smb_commands! {
    Create = cmd::CREATE => CreateReq, CreateCmd;
    Lock   = cmd::LOCK   => LockReq,   LockCmd;
    Echo   = cmd::ECHO   => EchoReq,   EchoCmd;   // body-less cmds use a unit-ish req
    // …one line per command…
}
```

This keeps the generated surface obvious (an enum + two matches + a dispatch
fn), still fully **static** (the `match` monomorphizes, `Decode`/`serve` are
native-`async fn` calls), and **zero runtime cost** — macros are compile-time
only, so this is identical to the hand-written match from Section 5 but
impossible to desync. Body-less commands (ECHO/LOGOFF/TREE_DISCONNECT) use a
zero-field request struct with a trivial `Decode`, so the table stays uniform.

A second, smaller macro removes the sealed-marker boilerplate for the
*data-less* lifecycle states (states that carry data, like `Pending`, are still
written by hand because they have fields):

```rust
macro_rules! io_states {
    ( $( $state:ident ),+ $(,)? ) => {
        $( pub enum $state {}
           impl sealed::Sealed for $state {}
           impl IoState for $state {} )+
    };
}
io_states!(Accepted, Completed);   // Pending is hand-written: it holds async_id + cancel
```

### Where macros stop
Macros own only the **uniform** boilerplate. Do **not** macro-generate things
that legitimately vary or that hurt readability/`rustc` diagnostics:
- per-command **response layouts** (`build_*_resp`) — each has a distinct field
  layout; a macro there hides the wire format that reviewers need to see;
- `IoContext` **transition methods** — each transition is unique;
- anything where a macro would obscure a compile error's location.

Prefer **`macro_rules!`** (declarative, no proc-macro crate, no extra build-time
cost, readable expansion via `cargo expand`) over proc-macros; reach for a
proc-macro only if we ever need `#[derive(Decode)]`-style field parsing, and
measure the compile-time impact first.
