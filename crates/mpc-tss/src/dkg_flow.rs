//! One party of the complete distributed key generation: key generation, then
//! aux-info generation, ending in a share that can sign.
//!
//! The server (index 1) owns a [`DkgParty`]; the device owns a [`DeviceDkg`], which
//! runs the device share (index 0) and the recovery share (index 2). They exchange batches of [`WireMessage`]s, one batch per network round trip.
//! Messages carry a phase tag so that the two ceremonies cannot be confused
//! even when the other party is a step ahead and its aux-info messages arrive
//! before this party has finished key generation: they are held until needed.
//!
//! # Cost
//!
//! Aux-info generation needs Paillier primes, which are slow to generate. Pass
//! a [`PrimesSource`] that is already generating (or ready) when the party is
//! created, so that the ceremony does not wait on them.

use std::thread::JoinHandle;

use crate::aux_info::{
    complete_key_share, execution_id, generate_primes, spawn_aux_info_n, wallet_address,
    AuxInfoShare, FullKeyShare, Primes,
};
use crate::transport::{
    spawn_keygen_threshold, KeygenShare, ProtocolRunner, TransportError, WireMessage,
};

/// `WireMessage::phase` of key-generation messages.
pub const PHASE_KEYGEN: u8 = 0;
/// `WireMessage::phase` of aux-info messages.
pub const PHASE_AUX: u8 = 1;

/// Where a party gets the Paillier primes for the aux-info phase.
pub enum PrimesSource {
    /// Primes that are already available.
    Ready(Primes),
    /// Primes being generated on a background thread.
    Generating(JoinHandle<Primes>),
}

impl PrimesSource {
    /// Starts generating primes on a background thread now.
    pub fn generate_in_background() -> Self {
        PrimesSource::Generating(std::thread::spawn(generate_primes))
    }

    /// Waits for the primes if they are still being generated.
    fn into_primes(self) -> Result<Primes, TransportError> {
        match self {
            PrimesSource::Ready(primes) => Ok(primes),
            PrimesSource::Generating(handle) => handle.join().map_err(|_| {
                TransportError::Protocol("prime generation thread panicked".into())
            }),
        }
    }
}

/// What one call to [`DkgParty::step`] produced.
pub struct DkgStep {
    /// Messages to deliver to the other party, tagged with their phase.
    pub outgoing: Vec<WireMessage>,
    /// The completed key share, once both phases are done.
    pub output: Option<FullKeyShare>,
}

// Written by hand so the share is never printed.
impl std::fmt::Debug for DkgStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkgStep")
            .field("outgoing", &self.outgoing.len())
            .field("finished", &self.output.is_some())
            .finish()
    }
}

/// One party of the complete DKG.
pub struct DkgParty {
    index: u16,
    parties: u16,
    session_id: String,
    keygen: Option<ProtocolRunner<KeygenShare>>,
    aux: Option<ProtocolRunner<AuxInfoShare>>,
    primes: Option<PrimesSource>,
    incomplete: Option<KeygenShare>,
    /// Aux-info messages that arrived before this party reached the aux phase.
    pending_aux: Vec<WireMessage>,
    finished: bool,
}

impl DkgParty {
    /// Starts party `index` of a threshold DKG among `parties` parties, any
    /// `threshold` of which can sign. All parties must use the same
    /// `session_id`, `parties` and `threshold`.
    pub fn new_threshold(
        index: u16,
        parties: u16,
        threshold: u16,
        session_id: &str,
        primes: PrimesSource,
    ) -> Self {
        Self {
            index,
            parties,
            session_id: session_id.to_owned(),
            keygen: Some(spawn_keygen_threshold(
                index,
                parties,
                threshold,
                execution_id(session_id, "keygen"),
            )),
            aux: None,
            primes: Some(primes),
            incomplete: None,
            pending_aux: Vec::new(),
            finished: false,
        }
    }

    /// The EVM wallet address of a completed share.
    pub fn address_of(share: &FullKeyShare) -> Result<String, crate::MpcError> {
        wallet_address(share)
    }

    /// Delivers `incoming` and blocks until this party has nothing more to send
    /// until the next round, or has finished. Call with an empty batch to
    /// start. This can take long (prime generation, zero-knowledge proofs), so
    /// call it off any UI or async executor thread.
    pub fn step(&mut self, incoming: Vec<WireMessage>) -> Result<DkgStep, TransportError> {
        if self.finished {
            return Err(TransportError::RunnerStopped);
        }

        let mut keygen_in = Vec::new();
        let mut aux_in = Vec::new();
        for message in incoming {
            match message.phase {
                PHASE_KEYGEN => keygen_in.push(message),
                PHASE_AUX => aux_in.push(message),
                other => {
                    return Err(TransportError::Decode(format!("unknown phase {other}")));
                }
            }
        }

        let mut outgoing = Vec::new();

        if let Some(keygen) = self.keygen.as_mut() {
            let step = keygen.step(keygen_in)?;
            outgoing.extend(tag(step.outgoing, PHASE_KEYGEN));
            if let Some(share) = step.output {
                self.incomplete = Some(share);
                self.keygen = None;
                let primes = self
                    .primes
                    .take()
                    .ok_or(TransportError::RunnerStopped)?
                    .into_primes()?;
                self.aux = Some(spawn_aux_info_n(
                    self.index,
                    self.parties,
                    execution_id(&self.session_id, "aux"),
                    primes,
                ));
            }
        }
        // Key-generation messages that arrive after this party finished that
        // phase carry nothing it still needs.

        let Some(aux) = self.aux.as_mut() else {
            self.pending_aux.extend(aux_in);
            return Ok(DkgStep {
                outgoing,
                output: None,
            });
        };

        let mut batch = std::mem::take(&mut self.pending_aux);
        batch.extend(aux_in);
        let step = aux.step(batch)?;
        outgoing.extend(tag(step.outgoing, PHASE_AUX));

        let Some(aux_info) = step.output else {
            return Ok(DkgStep {
                outgoing,
                output: None,
            });
        };

        let incomplete = self.incomplete.take().ok_or(TransportError::RunnerStopped)?;
        let share = complete_key_share(incomplete, aux_info)
            .map_err(|e| TransportError::Protocol(e.to_string()))?;
        self.finished = true;
        Ok(DkgStep {
            outgoing,
            output: Some(share),
        })
    }

    /// Like [`step`](Self::step) on encoded batches, as carried by a gRPC round
    /// trip.
    pub fn step_bytes(
        &mut self,
        incoming: &[u8],
    ) -> Result<(Vec<u8>, Option<FullKeyShare>), TransportError> {
        let step = self.step(crate::transport::decode_batch(incoming)?)?;
        Ok((crate::transport::encode_batch(&step.outgoing)?, step.output))
    }
}

/// Index of the device's signing share in a 2-of-3 wallet.
pub const PARTY_DEVICE: u16 = 0;
/// Index of the server's share in a 2-of-3 wallet.
pub const PARTY_SERVER: u16 = 1;
/// Index of the recovery share in a 2-of-3 wallet.
pub const PARTY_RECOVERY: u16 = 2;
/// Parties in a 2-of-3 wallet.
pub const PARTIES: u16 = 3;
/// Signers needed in a 2-of-3 wallet.
pub const THRESHOLD: u16 = 2;

/// The two shares the device creates in a 2-of-3 DKG.
pub struct DeviceShares {
    /// The share kept on the device and used for everyday signing.
    pub device: FullKeyShare,
    /// The recovery share. Encrypt it and drop it right away. (The share object is dropped, not scrubbed; see the crate docs.)
    pub recovery: FullKeyShare,
}

impl std::fmt::Debug for DeviceShares {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceShares").finish_non_exhaustive()
    }
}

/// What one call to [`DeviceDkg::step`] produced.
#[derive(Debug)]
pub struct DeviceDkgStep {
    /// Messages for the server.
    pub outgoing: Vec<WireMessage>,
    /// Both shares, once the server and both local parties are done.
    pub output: Option<DeviceShares>,
}

/// The device's side of a 2-of-3 DKG: it runs the device party and the
/// recovery party in this process, passes their messages to each other, and
/// exchanges only the rest with the server (party 1).
///
/// Until [`step`](Self::step) returns the shares, this process holds two of
/// the three shares, enough to sign alone. Callers must therefore encrypt the
/// recovery share and drop it as soon as they receive it.
pub struct DeviceDkg {
    device: DkgParty,
    recovery: DkgParty,
    device_out: Option<FullKeyShare>,
    recovery_out: Option<FullKeyShare>,
    for_device: Vec<WireMessage>,
    for_recovery: Vec<WireMessage>,
}

impl DeviceDkg {
    /// Starts both local parties. `device_primes` and `recovery_primes` should
    /// already be generating, so the ceremony does not wait on them.
    pub fn new(session_id: &str, device_primes: PrimesSource, recovery_primes: PrimesSource) -> Self {
        Self {
            device: DkgParty::new_threshold(
                PARTY_DEVICE,
                PARTIES,
                THRESHOLD,
                session_id,
                device_primes,
            ),
            recovery: DkgParty::new_threshold(
                PARTY_RECOVERY,
                PARTIES,
                THRESHOLD,
                session_id,
                recovery_primes,
            ),
            device_out: None,
            recovery_out: None,
            for_device: Vec::new(),
            for_recovery: Vec::new(),
        }
    }

    /// Delivers the server's `incoming` messages and returns what to send back.
    /// Blocks while the local parties compute, so call it off any UI thread.
    /// Call with an empty batch to start.
    pub fn step(&mut self, incoming: Vec<WireMessage>) -> Result<DeviceDkgStep, TransportError> {
        for message in incoming {
            if message.sender != PARTY_SERVER {
                return Err(TransportError::Decode(format!(
                    "unexpected sender {}; only the server is remote",
                    message.sender
                )));
            }
            match message.recipient {
                None => {
                    self.for_device.push(message.clone());
                    self.for_recovery.push(message);
                }
                Some(PARTY_DEVICE) => self.for_device.push(message),
                Some(PARTY_RECOVERY) => self.for_recovery.push(message),
                Some(other) => {
                    return Err(TransportError::WrongRecipient {
                        recipient: other,
                        this_party: PARTY_DEVICE,
                    })
                }
            }
        }

        let mut to_server = Vec::new();
        // Give each local party a turn until neither has anything left to
        // read. A party that has finished ignores late messages.
        let mut first_round = true;
        loop {
            let mut worked = false;

            if self.device_out.is_none() && (first_round || !self.for_device.is_empty()) {
                let inbox = std::mem::take(&mut self.for_device);
                let step = self.device.step(inbox)?;
                worked |= !step.outgoing.is_empty() || step.output.is_some();
                route(step.outgoing, PARTY_RECOVERY, &mut self.for_recovery, &mut to_server);
                self.device_out = step.output;
            } else {
                self.for_device.clear();
            }

            if self.recovery_out.is_none() && (first_round || !self.for_recovery.is_empty()) {
                let inbox = std::mem::take(&mut self.for_recovery);
                let step = self.recovery.step(inbox)?;
                worked |= !step.outgoing.is_empty() || step.output.is_some();
                route(step.outgoing, PARTY_DEVICE, &mut self.for_device, &mut to_server);
                self.recovery_out = step.output;
            } else {
                self.for_recovery.clear();
            }

            first_round = false;
            if !worked {
                break;
            }
        }

        let output = match (self.device_out.take(), self.recovery_out.take()) {
            (Some(device), Some(recovery)) => Some(DeviceShares { device, recovery }),
            (device, recovery) => {
                self.device_out = device;
                self.recovery_out = recovery;
                None
            }
        };
        Ok(DeviceDkgStep {
            outgoing: to_server,
            output,
        })
    }

    /// Like [`step`](Self::step) on encoded batches.
    pub fn step_bytes(
        &mut self,
        incoming: &[u8],
    ) -> Result<(Vec<u8>, Option<DeviceShares>), TransportError> {
        let step = self.step(crate::transport::decode_batch(incoming)?)?;
        Ok((crate::transport::encode_batch(&step.outgoing)?, step.output))
    }
}

/// Sends a local party's messages to its local peer and, where the server must
/// see them, to the server.
fn route(
    messages: Vec<WireMessage>,
    peer: u16,
    peer_inbox: &mut Vec<WireMessage>,
    to_server: &mut Vec<WireMessage>,
) {
    for message in messages {
        match message.recipient {
            None => {
                peer_inbox.push(message.clone());
                to_server.push(message);
            }
            Some(r) if r == peer => peer_inbox.push(message),
            Some(_) => to_server.push(message),
        }
    }
}

fn tag(messages: Vec<WireMessage>, phase: u8) -> impl Iterator<Item = WireMessage> {
    messages.into_iter().map(move |mut m| {
        m.phase = phase;
        m
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(phase: u8) -> WireMessage {
        WireMessage {
            sender: 1,
            is_broadcast: true,
            phase,
            recipient: None,
            payload: vec![],
        }
    }

    #[test]
    fn unknown_phase_is_rejected() {
        let mut party = DkgParty::new_threshold(0, 3, 2, "s", PrimesSource::generate_in_background());
        let err = party.step(vec![message(9)]).unwrap_err();
        assert!(matches!(err, TransportError::Decode(_)));
    }

    #[test]
    fn aux_messages_that_arrive_early_are_held() {
        let mut party = DkgParty::new_threshold(0, 3, 2, "s", PrimesSource::generate_in_background());
        let step = party.step(vec![message(PHASE_AUX)]).unwrap();
        // Key generation started, so this party has its first messages ready,
        // and the early aux message was kept for later.
        assert!(!step.outgoing.is_empty());
        assert!(step.outgoing.iter().all(|m| m.phase == PHASE_KEYGEN));
        assert_eq!(party.pending_aux.len(), 1);
    }

    /// The device runs parties 0 and 2, the server runs party 1. Then every
    /// pair of shares signs: device+server, recovery+server, and device+recovery
    /// without the server. Slow because of prime generation (three parties):
    /// `cargo test -p khodpay-mpc-tss --release -- --ignored two_of_three`.
    #[test]
    #[ignore = "generates Paillier primes; slow, run explicitly with --ignored"]
    fn two_of_three_dkg_then_every_pair_signs() {
        use crate::aux_info::{
            execution_id, share_index, share_parties, share_threshold, sign_with_local_shares,
            signing_position, spawn_signing_subset,
        };
        use crate::signing::verify_signature_recovers_address;

        let mut device = DeviceDkg::new(
            "dkg-2of3",
            PrimesSource::generate_in_background(),
            PrimesSource::generate_in_background(),
        );
        let mut server = DkgParty::new_threshold(
            PARTY_SERVER,
            PARTIES,
            THRESHOLD,
            "dkg-2of3",
            PrimesSource::generate_in_background(),
        );

        let (mut for_device, mut for_server) = (Vec::new(), Vec::new());
        let (mut device_out, mut server_out) = (None, None);
        for _ in 0..300 {
            let mut progressed = false;
            if device_out.is_none() {
                let step = device.step(std::mem::take(&mut for_device)).unwrap();
                progressed |= !step.outgoing.is_empty() || step.output.is_some();
                for_server.extend(step.outgoing);
                device_out = step.output;
            }
            if server_out.is_none() {
                let step = server.step(std::mem::take(&mut for_server)).unwrap();
                progressed |= !step.outgoing.is_empty() || step.output.is_some();
                for_device.extend(step.outgoing);
                server_out = step.output;
            }
            if device_out.is_some() && server_out.is_some() {
                break;
            }
            assert!(progressed, "DKG stalled");
        }

        let DeviceShares { device: a, recovery: c } = device_out.expect("device finished");
        let b = server_out.expect("server finished");
        assert_eq!(
            (share_index(&a), share_index(&b), share_index(&c)),
            (PARTY_DEVICE, PARTY_SERVER, PARTY_RECOVERY)
        );
        assert_eq!((share_parties(&a), share_threshold(&a)), (3, 2));

        let address = DkgParty::address_of(&a).unwrap();
        assert_eq!(address, DkgParty::address_of(&b).unwrap());
        assert_eq!(address, DkgParty::address_of(&c).unwrap());

        let hash = [0x24u8; 32];

        // Everyday signing and server-assisted recovery: one local share plus
        // the server share, over the transport.
        for (name, local, group) in [
            ("device+server", a.clone(), vec![PARTY_DEVICE, PARTY_SERVER]),
            ("recovery+server", c.clone(), vec![PARTY_SERVER, PARTY_RECOVERY]),
        ] {
            let sid = format!("sign-{name}");
            let eid = execution_id(&sid, "sign");
            let local_pos = signing_position(&group, share_index(&local)).unwrap();
            let server_pos = signing_position(&group, PARTY_SERVER).unwrap();
            let (mut x, mut y) = (
                spawn_signing_subset(local_pos, group.clone(), eid, local, hash),
                spawn_signing_subset(server_pos, group.clone(), eid, b.clone(), hash),
            );
            let (mut for_x, mut for_y) = (Vec::new(), Vec::new());
            let (mut out_x, mut out_y) = (None, None);
            for _ in 0..200 {
                if out_x.is_none() {
                    let s = x.step(std::mem::take(&mut for_x)).unwrap();
                    for_y.extend(s.outgoing);
                    out_x = s.output;
                }
                if out_y.is_none() {
                    let s = y.step(std::mem::take(&mut for_y)).unwrap();
                    for_x.extend(s.outgoing);
                    out_y = s.output;
                }
                if out_x.is_some() && out_y.is_some() {
                    break;
                }
            }
            let (sx, sy): ([u8; 65], [u8; 65]) = (out_x.expect(name), out_y.expect(name));
            assert_eq!(sx, sy, "{name}: both parties get the same signature");
            assert!(verify_signature_recovers_address(&sx, hash, &address), "{name}");
        }

        // Recovery without the server.
        let local = sign_with_local_shares(c, a, "sign-local", hash).unwrap();
        assert!(verify_signature_recovers_address(&local, hash, &address));
    }

}
