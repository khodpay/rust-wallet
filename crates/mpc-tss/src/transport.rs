//! Round-by-round transport for CGGMP21 ceremonies.
//!
//! The `cggmp21` protocols (key generation, aux-info generation, signing) are
//! message-passing state machines. In production the two parties live in
//! different processes, so each network round trip carries a *batch* of
//! protocol messages. This module provides:
//!
//! * [`WireMessage`] and [`encode_batch`] / [`decode_batch`]: the wire format
//!   shared by the device and the server.
//! * [`ProtocolRunner`]: runs one party of a ceremony on a worker thread and
//!   exposes a blocking `step(incoming) -> outgoing` call. The worker owns the
//!   key share, the RNG and the execution id, so no borrowed data has to
//!   outlive a call and secrets are dropped with the thread.
//!
//! Point-to-point messages carry the index of their recipient, so any number of
//! parties can be addressed. A runner drives exactly one party; routing between
//! several parties that share a process is done by the caller (see
//! [`crate::dkg_flow::DeviceDkg`]).

use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};

use round_based::state_machine::{ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Largest batch accepted by [`decode_batch`], in bytes.
pub const MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// Errors raised while moving protocol messages or driving a ceremony.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TransportError {
    /// A message or batch could not be encoded.
    #[error("failed to encode protocol message: {0}")]
    Encode(String),
    /// A message or batch could not be decoded, or was too large.
    #[error("failed to decode protocol message: {0}")]
    Decode(String),
    /// The peer sent a message claiming to come from this party.
    #[error("received a message with sender index {0}, which is this party")]
    SenderIsSelf(u16),
    /// A point-to-point message was addressed to a different party.
    #[error("message is for party {recipient}, not for party {this_party}")]
    WrongRecipient {
        /// The party the message was addressed to.
        recipient: u16,
        /// The party that received it.
        this_party: u16,
    },
    /// The protocol asked for something the transport cannot do.
    #[error("unsupported message destination")]
    UnsupportedDestination,
    /// The protocol state machine reported an error.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The worker thread stopped (finished, failed, or panicked).
    #[error("the protocol worker is no longer running")]
    RunnerStopped,
}

/// One protocol message on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireMessage {
    /// Index of the party that produced the message.
    pub sender: u16,
    /// `true` for a broadcast message, `false` for a point-to-point message.
    pub is_broadcast: bool,
    /// Which ceremony of a multi-phase flow the message belongs to (for
    /// example key generation or aux info). Single-phase flows leave it at 0.
    #[serde(default)]
    pub phase: u8,
    /// For a point-to-point message, the index of the party it is for. `None`
    /// for broadcasts and in two-party flows, where the other party is the only
    /// possible recipient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<u16>,
    /// The CBOR-encoded protocol message.
    pub payload: Vec<u8>,
}

/// Encodes a batch of messages for one network round trip.
pub fn encode_batch(messages: &[WireMessage]) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(messages, &mut out)
        .map_err(|e| TransportError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decodes a batch produced by [`encode_batch`]. An empty input is an empty
/// batch, which is how a party is asked to start.
pub fn decode_batch(bytes: &[u8]) -> Result<Vec<WireMessage>, TransportError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(TransportError::Decode(format!(
            "batch is {} bytes; the maximum is {MAX_BATCH_BYTES}",
            bytes.len()
        )));
    }
    ciborium::de::from_reader(bytes).map_err(|e| TransportError::Decode(e.to_string()))
}

fn encode_message<M: Serialize>(msg: &M) -> Result<Vec<u8>, TransportError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(msg, &mut out).map_err(|e| TransportError::Encode(e.to_string()))?;
    Ok(out)
}

fn decode_message<M: DeserializeOwned>(bytes: &[u8]) -> Result<M, TransportError> {
    ciborium::de::from_reader(bytes).map_err(|e| TransportError::Decode(e.to_string()))
}

// ─── Single-party driver ─────────────────────────────────────────────────────

/// What one call to [`ProtocolRunner::step`] produced.
pub struct Step<O> {
    /// Messages to deliver to the other party.
    pub outgoing: Vec<WireMessage>,
    /// The ceremony result, once this party has finished.
    pub output: Option<O>,
}

// Written by hand so the output (usually secret key material) is never printed.
impl<O> std::fmt::Debug for Step<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Step")
            .field("outgoing", &self.outgoing.len())
            .field("finished", &self.output.is_some())
            .finish()
    }
}

/// Feeds incoming messages into one party's state machine and collects what it
/// wants to send.
struct Driver<SM: StateMachine> {
    sm: SM,
    index: u16,
    next_id: u64,
    /// The state machine asked for a message and has not received one yet.
    awaiting: bool,
}

impl<SM> Driver<SM>
where
    SM: StateMachine,
    SM::Msg: Serialize + DeserializeOwned,
{
    fn new(sm: SM, index: u16) -> Self {
        Self {
            sm,
            index,
            next_id: 0,
            awaiting: false,
        }
    }

    fn step(&mut self, incoming: Vec<WireMessage>) -> Result<Step<SM::Output>, TransportError> {
        let mut queue: VecDeque<Incoming<SM::Msg>> = VecDeque::with_capacity(incoming.len());
        for wire in incoming {
            if wire.sender == self.index {
                return Err(TransportError::SenderIsSelf(wire.sender));
            }
            if let Some(to) = wire.recipient {
                if to != self.index {
                    return Err(TransportError::WrongRecipient {
                        recipient: to,
                        this_party: self.index,
                    });
                }
            }
            let id = self.next_id;
            self.next_id += 1;
            queue.push_back(Incoming {
                id,
                sender: wire.sender,
                msg_type: if wire.is_broadcast {
                    MessageType::Broadcast
                } else {
                    MessageType::P2P
                },
                msg: decode_message(&wire.payload)?,
            });
        }

        let mut outgoing = Vec::new();
        loop {
            if self.awaiting {
                // A state machine that asked for a message must be given one
                // before it is resumed. With nothing queued we wait for the
                // next network round.
                let Some(msg) = queue.pop_front() else {
                    return Ok(Step {
                        outgoing,
                        output: None,
                    });
                };
                self.sm.received_msg(msg).map_err(|_| {
                    TransportError::Protocol("state machine rejected a received message".into())
                })?;
                self.awaiting = false;
            }

            match self.sm.proceed() {
                ProceedResult::SendMsg(out) => outgoing.push(self.to_wire(out)?),
                ProceedResult::NeedsOneMoreMessage => self.awaiting = true,
                ProceedResult::Yielded => {}
                ProceedResult::Output(output) => {
                    return Ok(Step {
                        outgoing,
                        output: Some(output),
                    })
                }
                ProceedResult::Error(e) => return Err(TransportError::Protocol(e.to_string())),
            }
        }
    }

    fn to_wire(&self, out: Outgoing<SM::Msg>) -> Result<WireMessage, TransportError> {
        let (is_broadcast, recipient) = match out.recipient {
            MessageDestination::AllParties => (true, None),
            // Addressing ourselves would be a protocol bug.
            MessageDestination::OneParty(to) if to != self.index => (false, Some(to)),
            MessageDestination::OneParty(_) => return Err(TransportError::UnsupportedDestination),
        };
        Ok(WireMessage {
            sender: self.index,
            is_broadcast,
            phase: 0,
            recipient,
            payload: encode_message(&out.msg)?,
        })
    }
}

// ─── Worker-thread runner ────────────────────────────────────────────────────

type StepResult<O> = Result<Step<O>, TransportError>;

/// The worker side of a [`ProtocolRunner`]: receives message batches and sends
/// back [`Step`]s. Handed to the closure passed to [`ProtocolRunner::spawn`].
pub struct Worker<O> {
    incoming: Receiver<Vec<WireMessage>>,
    results: Sender<StepResult<O>>,
}

impl<O> Worker<O> {
    /// Ends the ceremony before it starts, reporting `error` to the caller.
    ///
    /// Use it when the worker cannot even build its state machine (for example
    /// because the key share is unusable). It waits for the first request so the
    /// caller sees `error`, not a generic "worker stopped".
    pub fn fail(self, error: TransportError) {
        let _ = self.incoming.recv();
        let _ = self.results.send(Err(error));
    }
}

/// Runs the state machine `sm` until it produces its output or fails.
///
/// `finish` converts the protocol's own output type into `O`. Call this from
/// the closure given to [`ProtocolRunner::spawn`], after building `sm` from
/// data that the closure owns.
pub fn drive<SM, O, F>(worker: Worker<O>, sm: SM, index: u16, finish: F)
where
    SM: StateMachine,
    SM::Msg: Serialize + DeserializeOwned,
    F: FnOnce(SM::Output) -> Result<O, TransportError>,
{
    let mut driver = Driver::new(sm, index);
    let mut finish = Some(finish);

    while let Ok(batch) = worker.incoming.recv() {
        let result = driver.step(batch).and_then(|step| {
            let output = match step.output {
                Some(raw) => {
                    let finish = finish.take().ok_or(TransportError::RunnerStopped)?;
                    Some(finish(raw)?)
                }
                None => None,
            };
            Ok(Step {
                outgoing: step.outgoing,
                output,
            })
        });

        let done = match &result {
            Ok(step) => step.output.is_some(),
            Err(_) => true,
        };
        if worker.results.send(result).is_err() || done {
            break;
        }
    }
}

/// One party of a ceremony, running on its own thread.
///
/// The worker owns the key share, the RNG and the execution id, so the state
/// machine can borrow them without any of it having to outlive a call.
/// Dropping the runner closes the channel; the worker then stops after the
/// computation it is currently doing.
pub struct ProtocolRunner<O> {
    to_worker: Sender<Vec<WireMessage>>,
    from_worker: Receiver<StepResult<O>>,
}

impl<O: Send + 'static> ProtocolRunner<O> {
    /// Starts a worker thread running `body`.
    pub fn spawn<F>(body: F) -> Self
    where
        F: FnOnce(Worker<O>) + Send + 'static,
    {
        let (to_worker, incoming) = mpsc::channel();
        let (results, from_worker) = mpsc::channel();
        std::thread::spawn(move || body(Worker { incoming, results }));
        Self {
            to_worker,
            from_worker,
        }
    }

    /// Delivers `incoming` to the party and blocks until it has nothing more
    /// to send until the next round, or has finished. Call with an empty batch
    /// to start the party.
    pub fn step(&mut self, incoming: Vec<WireMessage>) -> Result<Step<O>, TransportError> {
        self.to_worker
            .send(incoming)
            .map_err(|_| TransportError::RunnerStopped)?;
        self.from_worker
            .recv()
            .map_err(|_| TransportError::RunnerStopped)?
    }

    /// Like [`step`](Self::step), but takes and returns encoded batches, which
    /// is what a gRPC round trip carries.
    pub fn step_bytes(
        &mut self,
        incoming: &[u8],
    ) -> Result<(Vec<u8>, Option<O>), TransportError> {
        let step = self.step(decode_batch(incoming)?)?;
        Ok((encode_batch(&step.outgoing)?, step.output))
    }
}

// ─── Key generation ──────────────────────────────────────────────────────────

/// The key share produced by key generation. It cannot sign until aux info has
/// been generated and combined with it.
pub type KeygenShare = cggmp21::IncompleteKeyShare<cggmp21::supported_curves::Secp256k1>;

/// Starts one party of a threshold CGGMP21 key generation: `parties` take part
/// and any `threshold` of them can later sign.
///
/// All parties must use the same `execution_id`, `parties` and `threshold`,
/// and distinct `index` values in `0..parties`.
pub fn spawn_keygen_threshold(
    index: u16,
    parties: u16,
    threshold: u16,
    execution_id: [u8; 32],
) -> ProtocolRunner<KeygenShare> {
    use cggmp21::{supported_curves::Secp256k1, ExecutionId};
    use rand::rngs::OsRng;

    ProtocolRunner::spawn(move |worker| {
        let eid = ExecutionId::new(&execution_id);
        let mut rng = OsRng;
        let sm = cggmp21::keygen::<Secp256k1>(eid, index, parties)
            .set_threshold(threshold)
            .into_state_machine(&mut rng);
        drive(worker, sm, index, |result| {
            result
                .map(Into::into)
                .map_err(|e| TransportError::Protocol(format!("key generation failed: {e}")))
        });
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const EID: [u8; 32] = [7u8; 32];

    /// Exchanges batches between two runners until both have an output, like
    /// the device and the server would over the network.
    pub(crate) fn run_pair<O: Send + 'static>(
        mut a: ProtocolRunner<O>,
        mut b: ProtocolRunner<O>,
    ) -> (O, O) {
        let (mut for_a, mut for_b) = (Vec::new(), Vec::new());
        let (mut out_a, mut out_b) = (None, None);

        for _ in 0..200 {
            let mut progressed = false;
            if out_a.is_none() {
                let step = a.step(std::mem::take(&mut for_a)).expect("party 0 step");
                progressed |= !step.outgoing.is_empty() || step.output.is_some();
                for_b.extend(step.outgoing);
                out_a = step.output;
            }
            if out_b.is_none() {
                let step = b.step(std::mem::take(&mut for_b)).expect("party 1 step");
                progressed |= !step.outgoing.is_empty() || step.output.is_some();
                for_a.extend(step.outgoing);
                out_b = step.output;
            }
            if out_a.is_some() && out_b.is_some() {
                return (out_a.unwrap(), out_b.unwrap());
            }
            assert!(progressed, "ceremony stalled: neither party made progress");
        }
        panic!("ceremony did not finish within 200 network rounds");
    }

    #[test]
    fn batch_round_trips() {
        let batch = vec![
            WireMessage {
                sender: 0,
                is_broadcast: true,
                phase: 0,
                recipient: None,
                payload: vec![1, 2, 3],
            },
            WireMessage {
                sender: 1,
                is_broadcast: false,
                phase: 1,
                recipient: None,
                payload: vec![],
            },
        ];
        let bytes = encode_batch(&batch).unwrap();
        assert_eq!(decode_batch(&bytes).unwrap(), batch);
    }

    #[test]
    fn empty_bytes_are_an_empty_batch() {
        assert!(decode_batch(&[]).unwrap().is_empty());
    }

    #[test]
    fn garbage_batch_is_rejected() {
        assert!(matches!(
            decode_batch(&[0xff, 0xff, 0xff]),
            Err(TransportError::Decode(_))
        ));
    }

    #[test]
    fn oversized_batch_is_rejected() {
        let big = vec![0u8; MAX_BATCH_BYTES + 1];
        assert!(matches!(decode_batch(&big), Err(TransportError::Decode(_))));
    }

    #[test]
    fn keygen_over_the_transport_yields_matching_shares() {
        let (device, server) = run_pair(spawn_keygen_threshold(0, 2, 2, EID), spawn_keygen_threshold(1, 2, 2, EID));
        assert_eq!(
            device.shared_public_key(),
            server.shared_public_key(),
            "both parties must derive the same joint public key"
        );
    }

    #[test]
    fn keygen_works_through_encoded_batches() {
        let mut device = spawn_keygen_threshold(0, 2, 2, [9u8; 32]);
        let mut server = spawn_keygen_threshold(1, 2, 2, [9u8; 32]);
        let (mut to_server, mut to_device) = (Vec::new(), Vec::new());
        let (mut device_out, mut server_out) = (None, None);

        for _ in 0..200 {
            if device_out.is_none() {
                let (bytes, out) = device.step_bytes(&to_device).unwrap();
                to_server = bytes;
                device_out = out;
            }
            if server_out.is_none() {
                let (bytes, out) = server.step_bytes(&to_server).unwrap();
                to_device = bytes;
                server_out = out;
            }
            if device_out.is_some() && server_out.is_some() {
                break;
            }
        }
        assert_eq!(
            device_out.unwrap().shared_public_key(),
            server_out.unwrap().shared_public_key()
        );
    }

    #[test]
    fn a_message_claiming_to_be_from_self_is_rejected() {
        let mut party = spawn_keygen_threshold(0, 2, 2, EID);
        let forged = WireMessage {
            sender: 0,
            is_broadcast: true,
            phase: 0,
            recipient: None,
            payload: vec![0],
        };
        let err = party.step(vec![forged]).unwrap_err();
        assert_eq!(err, TransportError::SenderIsSelf(0));
    }

    #[test]
    fn a_stopped_runner_reports_it() {
        let mut party = spawn_keygen_threshold(0, 2, 2, EID);
        let forged = WireMessage {
            sender: 0,
            is_broadcast: true,
            phase: 0,
            recipient: None,
            payload: vec![0],
        };
        let _ = party.step(vec![forged]);
        assert_eq!(party.step(vec![]).unwrap_err(), TransportError::RunnerStopped);
    }
}
