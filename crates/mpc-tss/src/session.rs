//! Session state machine shared by DKG, signing, and resharing.
//!
//! Every MPC operation (DKG, signing, resharing) is modelled as a series of
//! network rounds.  [`MpcSession`] tracks the current state of one such
//! operation via [`SessionState`].  Round payloads exchanged with the server
//! are represented as [`RoundPayload`] — an opaque byte blob that maps
//! directly to the `round_payload` field in the gRPC wire format.
//!
//! # State machine
//!
//! ```text
//!                 ┌──────────┐
//!                 │ Pending  │  ← initial state on creation
//!                 └────┬─────┘
//!                      │ advance_round(1)
//!                      ▼
//!              ┌────────────────┐
//!              │ InProgress {   │  ← one per network round
//!              │   round: u8    │
//!              └──────┬─────┬──┘
//!          complete() │     │ fail(e)
//!                     ▼     ▼
//!               ┌──────┐ ┌────────────────┐
//!               │Complete│ │ Failed(MpcError)│
//!               └────────┘ └────────────────┘
//! ```
//!
//! `Complete` and `Failed` are terminal — attempting a further transition
//! returns [`MpcError::ProtocolViolation`].

use uuid::Uuid;

use crate::error::{MpcError, Result};

// ─── RoundPayload ────────────────────────────────────────────────────────────

/// Opaque wire bytes for one protocol round.
///
/// This newtype wraps the raw byte payload exchanged between the device and
/// the KhodPay signer server during a single round of a DKG, signing, or
/// resharing ceremony.  It maps directly to the `round_payload` field in the
/// gRPC contract.
///
/// The contents are intentionally opaque to callers — the internal structure
/// is determined by the underlying CGGMP21 protocol library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundPayload(Vec<u8>);

impl RoundPayload {
    /// Wraps raw bytes into a `RoundPayload`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the payload and returns the underlying byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for RoundPayload {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<RoundPayload> for Vec<u8> {
    fn from(p: RoundPayload) -> Self {
        p.0
    }
}

// ─── SessionState ────────────────────────────────────────────────────────────

/// The lifecycle state of an [`MpcSession`].
///
/// States progress through a linear sequence:
/// `Pending` → `InProgress` → `Complete` (or `Failed`).
/// `Complete` and `Failed` are terminal.
#[derive(Debug, Clone)]
pub enum SessionState {
    /// The session has been created but no round has been started yet.
    Pending,

    /// A round-trip with the server is in progress.
    ///
    /// `round` is the **1-indexed** current round number (round 1 is the
    /// first message sent to the server).
    InProgress {
        /// 1-indexed current protocol round.
        round: u8,
    },

    /// All protocol rounds completed successfully.  This is a terminal state.
    Complete,

    /// The protocol failed.  This is a terminal state.
    ///
    /// The embedded [`MpcError`] describes the failure mode.  Callers should
    /// not attempt to resume a failed session — create a new one instead.
    Failed(MpcError),
}

impl SessionState {
    /// Returns `true` if the session is in the `Complete` state.
    pub fn is_complete(&self) -> bool {
        matches!(self, SessionState::Complete)
    }

    /// Returns `true` if the session is in the `Failed` state.
    pub fn is_failed(&self) -> bool {
        matches!(self, SessionState::Failed(_))
    }

    /// Returns `true` if the state is terminal (`Complete` or `Failed`).
    fn is_terminal(&self) -> bool {
        self.is_complete() || self.is_failed()
    }
}

// ─── MpcSession ──────────────────────────────────────────────────────────────

/// Shared session state for a single DKG, signing, or resharing ceremony.
///
/// Each operation creates one `MpcSession`.  Higher-level types (`DkgSession`,
/// `SigningSession`, `ReshareSession`) wrap this struct and drive its state
/// transitions.
///
/// # Session ID
///
/// The session ID is a UUID v4 generated at construction time.  It is used
/// as the correlation key in the gRPC contract between the device and the
/// signer server.
pub struct MpcSession {
    session_id: String,
    state: SessionState,
}

impl MpcSession {
    /// Creates a new `MpcSession` in the [`SessionState::Pending`] state with
    /// a freshly generated UUID v4 session ID.
    pub fn new() -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            state: SessionState::Pending,
        }
    }

    /// Returns the session ID (UUID v4 string).
    ///
    /// This value is stable for the lifetime of the session and must be
    /// forwarded to the signer server in every round message.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns a reference to the current [`SessionState`].
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Returns `true` if the session is [`SessionState::Complete`].
    pub fn is_complete(&self) -> bool {
        self.state.is_complete()
    }

    /// Returns `true` if the session is [`SessionState::Failed`].
    pub fn is_failed(&self) -> bool {
        self.state.is_failed()
    }

    /// Transitions from [`SessionState::Pending`] or
    /// [`SessionState::InProgress`] to `InProgress { round }`.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::ProtocolViolation`] if the session is already in a
    /// terminal state (`Complete` or `Failed`).
    pub fn advance_round(&mut self, round: u8) -> Result<()> {
        if self.state.is_terminal() {
            return Err(MpcError::ProtocolViolation {
                reason: format!(
                    "cannot advance round on a terminal session (state: {:?})",
                    self.state
                ),
            });
        }
        self.state = SessionState::InProgress { round };
        Ok(())
    }

    /// Transitions the session to [`SessionState::Complete`].
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::ProtocolViolation`] if the session is already in a
    /// terminal state.
    pub fn complete(&mut self) -> Result<()> {
        if self.state.is_terminal() {
            return Err(MpcError::ProtocolViolation {
                reason: format!(
                    "cannot complete an already-terminal session (state: {:?})",
                    self.state
                ),
            });
        }
        self.state = SessionState::Complete;
        Ok(())
    }

    /// Transitions the session to [`SessionState::Failed`] with the given
    /// error.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::ProtocolViolation`] if the session is already in a
    /// terminal state.
    pub fn fail(&mut self, error: MpcError) -> Result<()> {
        if self.state.is_terminal() {
            return Err(MpcError::ProtocolViolation {
                reason: format!(
                    "cannot fail an already-terminal session (state: {:?})",
                    self.state
                ),
            });
        }
        self.state = SessionState::Failed(error);
        Ok(())
    }
}

impl Default for MpcSession {
    fn default() -> Self {
        Self::new()
    }
}

/// `MpcSession` is intentionally not `Clone` — each session is a unique
/// cryptographic context.  Cloning would risk share reuse.
impl std::fmt::Debug for MpcSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcSession")
            .field("session_id", &self.session_id)
            .field("state", &self.state)
            .finish()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RoundPayload ────────────────────────────────────────────────────────

    #[test]
    fn test_round_payload_new_and_as_bytes() {
        let payload = RoundPayload::new(vec![1, 2, 3]);
        assert_eq!(payload.as_bytes(), &[1u8, 2, 3]);
    }

    #[test]
    fn test_round_payload_into_bytes() {
        let payload = RoundPayload::new(vec![10, 20, 30]);
        let bytes = payload.into_bytes();
        assert_eq!(bytes, vec![10u8, 20, 30]);
    }

    #[test]
    fn test_round_payload_from_vec() {
        let payload: RoundPayload = vec![0xAB, 0xCD].into();
        assert_eq!(payload.as_bytes(), &[0xABu8, 0xCD]);
    }

    #[test]
    fn test_round_payload_into_vec() {
        let payload = RoundPayload::new(vec![7, 8, 9]);
        let v: Vec<u8> = payload.into();
        assert_eq!(v, vec![7u8, 8, 9]);
    }

    #[test]
    fn test_round_payload_eq() {
        let a = RoundPayload::new(vec![1, 2]);
        let b = RoundPayload::new(vec![1, 2]);
        let c = RoundPayload::new(vec![1, 3]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_round_payload_clone() {
        let a = RoundPayload::new(vec![42]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_round_payload_empty() {
        let payload = RoundPayload::new(vec![]);
        assert_eq!(payload.as_bytes(), &[] as &[u8]);
    }

    // ── SessionState flags ──────────────────────────────────────────────────

    #[test]
    fn test_state_pending_is_not_complete_or_failed() {
        let s = SessionState::Pending;
        assert!(!s.is_complete());
        assert!(!s.is_failed());
        assert!(!s.is_terminal());
    }

    #[test]
    fn test_state_in_progress_is_not_terminal() {
        let s = SessionState::InProgress { round: 1 };
        assert!(!s.is_complete());
        assert!(!s.is_failed());
        assert!(!s.is_terminal());
    }

    #[test]
    fn test_state_complete_flags() {
        let s = SessionState::Complete;
        assert!(s.is_complete());
        assert!(!s.is_failed());
        assert!(s.is_terminal());
    }

    #[test]
    fn test_state_failed_flags() {
        let s = SessionState::Failed(MpcError::DkgFailed {
            reason: "test".into(),
        });
        assert!(!s.is_complete());
        assert!(s.is_failed());
        assert!(s.is_terminal());
    }

    // ── MpcSession creation ─────────────────────────────────────────────────

    #[test]
    fn test_new_session_starts_pending() {
        let session = MpcSession::new();
        assert!(matches!(session.state(), SessionState::Pending));
        assert!(!session.is_complete());
        assert!(!session.is_failed());
    }

    #[test]
    fn test_session_id_is_valid_uuid_v4() {
        let session = MpcSession::new();
        let id = session.session_id();
        // UUID v4 string is 36 characters: 8-4-4-4-12
        assert_eq!(id.len(), 36);
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        // Version nibble must be '4'
        assert_eq!(&parts[2][0..1], "4");
        // Variant bits: first char of parts[3] must be '8', '9', 'a', or 'b'
        let variant_char = parts[3].chars().next().unwrap();
        assert!(
            matches!(variant_char, '8' | '9' | 'a' | 'b'),
            "UUID variant char must be 8/9/a/b, got: {}",
            variant_char
        );
    }

    #[test]
    fn test_session_ids_are_unique() {
        let ids: Vec<String> = (0..100)
            .map(|_| MpcSession::new().session_id().to_string())
            .collect();
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), 100, "all 100 session IDs must be unique");
    }

    #[test]
    fn test_default_equals_new() {
        let session = MpcSession::default();
        assert!(matches!(session.state(), SessionState::Pending));
    }

    // ── State transitions ───────────────────────────────────────────────────

    #[test]
    fn test_pending_to_in_progress_round_1() {
        let mut session = MpcSession::new();
        session.advance_round(1).expect("advance_round(1) must succeed from Pending");
        assert!(matches!(session.state(), SessionState::InProgress { round: 1 }));
    }

    #[test]
    fn test_in_progress_round_advances() {
        let mut session = MpcSession::new();
        session.advance_round(1).unwrap();
        session.advance_round(2).expect("advance_round(2) must succeed from InProgress");
        assert!(matches!(session.state(), SessionState::InProgress { round: 2 }));
    }

    #[test]
    fn test_advance_multiple_rounds() {
        let mut session = MpcSession::new();
        for round in 1u8..=5 {
            session.advance_round(round).unwrap();
            assert!(matches!(
                session.state(),
                SessionState::InProgress { round: r } if *r == round
            ));
        }
    }

    #[test]
    fn test_pending_to_complete() {
        let mut session = MpcSession::new();
        session.complete().expect("complete() must succeed from Pending");
        assert!(session.is_complete());
        assert!(matches!(session.state(), SessionState::Complete));
    }

    #[test]
    fn test_in_progress_to_complete() {
        let mut session = MpcSession::new();
        session.advance_round(1).unwrap();
        session.complete().expect("complete() must succeed from InProgress");
        assert!(session.is_complete());
    }

    #[test]
    fn test_pending_to_failed() {
        let mut session = MpcSession::new();
        session
            .fail(MpcError::DkgFailed {
                reason: "network error".into(),
            })
            .expect("fail() must succeed from Pending");
        assert!(session.is_failed());
        assert!(matches!(session.state(), SessionState::Failed(_)));
    }

    #[test]
    fn test_in_progress_to_failed() {
        let mut session = MpcSession::new();
        session.advance_round(1).unwrap();
        session
            .fail(MpcError::NetworkRoundFailed {
                round: 1,
                reason: "timeout".into(),
            })
            .expect("fail() must succeed from InProgress");
        assert!(session.is_failed());
    }

    // ── Terminal-state guard: double-complete ───────────────────────────────

    #[test]
    fn test_double_complete_returns_protocol_violation() {
        let mut session = MpcSession::new();
        session.complete().unwrap();
        let err = session
            .complete()
            .expect_err("second complete() must fail");
        assert!(
            matches!(err, MpcError::ProtocolViolation { .. }),
            "expected ProtocolViolation, got: {:?}",
            err
        );
    }

    #[test]
    fn test_complete_then_fail_returns_protocol_violation() {
        let mut session = MpcSession::new();
        session.complete().unwrap();
        let err = session
            .fail(MpcError::DkgFailed {
                reason: "late error".into(),
            })
            .expect_err("fail() after complete must return an error");
        assert!(matches!(err, MpcError::ProtocolViolation { .. }));
    }

    #[test]
    fn test_fail_then_complete_returns_protocol_violation() {
        let mut session = MpcSession::new();
        session
            .fail(MpcError::SigningFailed {
                reason: "bad sig".into(),
            })
            .unwrap();
        let err = session
            .complete()
            .expect_err("complete() after fail must return an error");
        assert!(matches!(err, MpcError::ProtocolViolation { .. }));
    }

    #[test]
    fn test_double_fail_returns_protocol_violation() {
        let mut session = MpcSession::new();
        session
            .fail(MpcError::DkgFailed {
                reason: "first".into(),
            })
            .unwrap();
        let err = session
            .fail(MpcError::DkgFailed {
                reason: "second".into(),
            })
            .expect_err("second fail() must return an error");
        assert!(matches!(err, MpcError::ProtocolViolation { .. }));
    }

    #[test]
    fn test_advance_round_on_complete_returns_protocol_violation() {
        let mut session = MpcSession::new();
        session.complete().unwrap();
        let err = session
            .advance_round(1)
            .expect_err("advance_round() on Complete must fail");
        assert!(matches!(err, MpcError::ProtocolViolation { .. }));
    }

    #[test]
    fn test_advance_round_on_failed_returns_protocol_violation() {
        let mut session = MpcSession::new();
        session
            .fail(MpcError::DkgFailed {
                reason: "oops".into(),
            })
            .unwrap();
        let err = session
            .advance_round(1)
            .expect_err("advance_round() on Failed must fail");
        assert!(matches!(err, MpcError::ProtocolViolation { .. }));
    }

    // ── Debug / Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_debug_contains_session_id() {
        let session = MpcSession::new();
        let id = session.session_id().to_string();
        let debug = format!("{:?}", session);
        assert!(
            debug.contains(&id),
            "Debug output must contain the session ID"
        );
    }

    #[test]
    fn test_mpc_session_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MpcSession>();
    }

    #[test]
    fn test_round_payload_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RoundPayload>();
    }
}
