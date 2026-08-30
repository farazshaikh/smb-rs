//! Typestate request/response pipeline (see `typestate_plan.md`).
//!
//! Phase 0 scaffolding: the lifecycle/origin marker traits, the `IoContext`
//! typestate, the `Decode`/`Encode`/`Command` traits, and the `smb_commands!`
//! table macro that generates the request sum type and its static dispatch.
//! Nothing here is wired into the live dispatcher yet; later phases migrate
//! commands onto it one cluster at a time while the regression gate stays green.
//!
//! Dispatch is static (a concrete `match` + monomorphic calls); the only dynamic
//! seam in the server is the transport, deliberately (see the plan's §12/§13).

#![allow(dead_code)] // scaffolding: most items are wired in later phases

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
/// its request type and handler. Generates `SmbRequest`, `SmbRequest::command`,
/// `SmbRequest::parse`, and the static `dispatch` function so a new command is
/// one line and cannot desync across those sites.
macro_rules! smb_commands {
    ( $( $variant:ident = $code:path => $req:ty , $handler:ty ; )* ) => {
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

        /// Static, monomorphic dispatch to the owning command handler (generated).
        pub async fn dispatch(ctx: IoContext<Accepted, Solicited>) -> Outcome {
            let (ctx, req) = ctx.split();
            match req {
                $( SmbRequest::$variant(r) => <$handler as Command>::serve(ctx, r).await, )*
            }
        }
    };
}

mod context;
mod origin;
mod request;
mod state;
mod wire;

pub use context::{Command, IoContext, Outcome};
pub use origin::{Bare, Origin, Solicited, Unsolicited};
pub use request::{dispatch, EchoCmd, EchoReq, SmbRequest};
pub use state::{Accepted, Completed, IoState, Pending};
pub use wire::{Decode, Encode, ReplyHeader, SealIntent, SmbResponse};
