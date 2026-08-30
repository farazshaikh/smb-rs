//! Lifecycle states of an [`IoContext`](super::IoContext).
//!
//! A state is a *type*: operations are only defined on the `IoContext<State>`
//! where they are legal, and a transition consumes the old state to yield the
//! new one, so illegal lifecycles fail to compile.

mod sealed {
    pub trait Sealed {}
}

/// A lifecycle state marker for an [`IoContext`](super::IoContext). Sealed: the
/// set of states is closed to this crate.
pub trait IoState: sealed::Sealed {}

// Data-less states (generated). `Accepted`: parsed and ready to serve.
// `Completed`: a final response has been produced and the context is spent.
io_states!(Accepted, Completed);

/// Deferred (STATUS_PENDING) state: an interim reply was sent and the final
/// reply is owed. Carries the async correlation id so it is *only* reachable
/// once a request has actually been deferred — you cannot complete work that was
/// never parked.
#[derive(Debug)]
pub struct Pending {
    pub(crate) async_id: u64,
}

impl sealed::Sealed for Pending {}
impl IoState for Pending {}
