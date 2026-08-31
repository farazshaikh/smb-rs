//! Typestate request/response pipeline (see `typestate_plan.md`).
//!
//! This is the live dispatch path: every SMB2 command the server answers is
//! decoded into a typed request ([`SmbRequest`]), moved into its owning
//! [`Command`] handler, and resolved to an [`Outcome`]. `smb2::process_single`
//! routes each command code here through `via_typestate` and then applies the
//! shared framing/crypto stage (pre-auth hash, signing, sealing) common to all
//! commands.
//!
//! Dispatch is static (a concrete `match` + monomorphic calls); the only dynamic
//! seam in the server is the transport, deliberately (see the plan's §12/§13).

#![allow(dead_code)] // some server-event scaffolding (Unsolicited origin) is unused pending Phase 5

/// Generate the data-less lifecycle state markers: a zero-sized struct plus its
/// sealed `IoState` impls. States that carry data (e.g. `Pending`) are written
/// by hand because they have fields.
macro_rules! io_states {
    ($($state:ident),+ $(,)?) => {
        $(
            #[derive(Debug, Clone, Copy)]
            pub struct $state;
            impl sealed::Sealed for $state {}
            impl IoState for $state {}
        )+
    };
}

/// The command table: the single source of truth mapping an SMB2 command code to
/// its request type. Generates `SmbRequest`, `SmbRequest::command`, and
/// `SmbRequest::parse`, so a decodable command is one line and cannot desync.
macro_rules! smb_request_table {
    ( $( $variant:ident = $code:path => $req:ty ; )* ) => {
        /// Sum type over every client request the server decodes (generated).
        #[derive(Debug)]
        pub enum SmbRequest { $( $variant($req), )* }

        impl SmbRequest {
            /// The SMB2 command code this request decodes to.
            pub fn command(&self) -> u16 {
                match self { $( SmbRequest::$variant(_) => $code, )* }
            }

            /// Decode one single-command frame selected by its command code.
            pub fn parse(command: u16, frame: &[u8]) -> Result<SmbRequest, Status> {
                match command {
                    $( $code => <$req as Decode>::decode(frame).map(SmbRequest::$variant), )*
                    _ => Err(Status::NOT_IMPLEMENTED),
                }
            }
        }
    };
}

/// Static, monomorphic dispatch to command handlers. Generated separately from
/// the request table so the two concerns stay decoupled; the `_` arm is
/// unreachable now that every decodable command has a handler, but is kept so a
/// future table-only addition still compiles.
macro_rules! smb_dispatch {
    ( $( $variant:ident => $handler:ty ; )* ) => {
        /// Serve a request by moving it into its owning handler (generated).
        pub async fn dispatch(
            ctx: IoContext<Accepted, Solicited>,
            res: &mut Resources<'_>,
        ) -> Outcome {
            let (ctx, req) = ctx.split();
            match req {
                $( SmbRequest::$variant(r) => <$handler as Command>::serve(ctx, r, res).await, )*
                #[allow(unreachable_patterns)]
                _ => Outcome::Silent,
            }
        }
    };
}

mod context;
mod decode;
mod origin;
mod request;
mod state;
mod wire;

pub use context::{Command, IoContext, Outcome, Resources};
pub use origin::{Bare, Origin, Solicited, Unsolicited};
pub use request::{dispatch, EchoCmd, EchoReq, SmbRequest};
pub use state::{Accepted, Completed, IoState, Pending};
pub use wire::{Decode, Encode, ReplyHeader, SealIntent, SmbResponse};
