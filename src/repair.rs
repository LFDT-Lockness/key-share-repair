//! Two-round triangular repair.
//!
//! Seats `0..t-1` are the helpers in increasing key-share index order.
//! Seat `t` is the repairing party. Each seat sends one point-to-point
//! message to every other seat per round. Pads, sigmas, and metadata are
//! `None` on edges the specification does not use. After round 2, the
//! repairing party checks the metadata locally. That check is round 3.

// Called from the crate tests only. There is no public entry point yet.
#![allow(dead_code)]

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use generic_ec_zkp::polynomial::lagrange_coefficient;
use key_share::{CoreKeyShare, DirtyKeyInfo};
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::simple_store::{RoundInput, RoundMsgs};
use round_based::rounds_router::RoundsRouter;
use round_based::{Delivery, Mpc, MpcParty, Outgoing};

use crate::errors::Error;
use crate::msg::{Msg, MsgRound1, MsgRound2, ShareMetadata};

/// One local party's inputs for a repair run.
pub(crate) struct Job<'a, E: Curve> {
    /// Domain-separation string for this key and this repair.
    pub sid: &'a [u8],
    /// `round-based` index of this party. Not a key-share index.
    pub seat: u16,
    /// Key-share index being restored.
    pub repairing: u16,
    /// Helper key-share indexes, strictly increasing.
    pub helpers: &'a [u16],
    /// Secret share for a helper, or public key info for the repairing party.
    pub role: Role<'a, E>,
    /// Adds one to this helper's sigma. Test builds only.
    #[cfg(test)]
    pub corrupt_sigma: bool,
}

/// Which side of the protocol this seat runs.
pub(crate) enum Role<'a, E: Curve> {
    /// Holds `x_h` and the public key record.
    Helper(&'a CoreKeyShare<E>),
    /// Holds the coordinator's copy of the public key record. No secret share.
    Repairing(&'a DirtyKeyInfo<E>),
}

struct Inputs<'a, E: Curve> {
    t: u16,
    n_parties: u16,
    shared_public_key: &'a NonZero<Point<E>>,
    public_shares: &'a [NonZero<Point<E>>],
    evaluation_points: &'a [NonZero<Scalar<E>>],
    #[cfg(feature = "hd-wallet")]
    chain_code: Option<[u8; 32]>,
    secret: Option<&'a NonZero<SecretScalar<E>>>,
}

/// Run repair for one seat.
///
/// Helpers return `Ok(None)`. The repairing party returns the restored share.
pub(crate) async fn run<E, R, M>(
    rng: &mut R,
    party: M,
    job: Job<'_, E>,
) -> Result<Option<NonZero<SecretScalar<E>>>, Error>
where
    E: Curve,
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E>>,
{
    let inputs = validate(&job)?;

    let outgoing_pads = sample_pads(rng, job.seat, inputs.t);
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<E>>::builder();
    let round1 = rounds.add_round(RoundInput::<MsgRound1<E>>::p2p(job.seat, inputs.n_parties));
    let round2 = rounds.add_round(RoundInput::<MsgRound2<E>>::p2p(job.seat, inputs.n_parties));
    let mut rounds = rounds.listen(incomings);

    send_to_others(&mut outgoings, inputs.n_parties, job.seat, |recipient| {
        Msg::Round1(MsgRound1 {
            pad: pad_on_edge(job.seat, recipient, inputs.t, &outgoing_pads),
        })
    })
    .await?;

    let round1_msgs = rounds.complete(round1).await.map_err(Error::receive)?;

    let payload = if job.seat == inputs.t {
        None
    } else {
        match helper_sigma(&job, &inputs, &outgoing_pads, &round1_msgs) {
            Ok(sigma) => Some((sigma, share_metadata(&job, &inputs))),
            Err(err) => {
                // An empty round 2 is not a share-dependent value. The router
                // still needs one round-2 message from this seat or the others block.
                exchange_round2(
                    &mut outgoings,
                    &mut rounds,
                    round2,
                    inputs.n_parties,
                    job.seat,
                    None,
                )
                .await?;
                return Err(err);
            }
        }
    };

    let round2_msgs = exchange_round2(
        &mut outgoings,
        &mut rounds,
        round2,
        inputs.n_parties,
        job.seat,
        payload,
    )
    .await?;

    if job.seat != inputs.t {
        return Ok(None);
    }
    metadata_matches(&job, &inputs, &round2_msgs)?;
    accept_share(&inputs, job.repairing, &round2_msgs)
}

fn validate<'a, E: Curve>(job: &Job<'a, E>) -> Result<Inputs<'a, E>, Error> {
    let info = match job.role {
        Role::Helper(share) => &share.key_info,
        Role::Repairing(info) => info,
    };
    let vss = info.vss_setup.as_ref().ok_or(Error::InvalidArgs)?;
    if info.public_shares.len() != vss.I.len() {
        return Err(Error::InvalidArgs);
    }
    let n = u16::try_from(info.public_shares.len()).map_err(|_| Error::InvalidArgs)?;
    let t = vss.min_signers;
    // `t <= n - 1` is the specification's `n >= t + 1`.
    if t < 2 || t >= n {
        return Err(Error::InvalidArgs);
    }
    if job.helpers.len() != usize::from(t) {
        return Err(Error::InvalidArgs);
    }
    if job.helpers.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::InvalidArgs);
    }
    if job.repairing >= n || job.helpers.contains(&job.repairing) {
        return Err(Error::InvalidArgs);
    }
    if job.helpers.iter().any(|helper| *helper >= n) {
        return Err(Error::InvalidArgs);
    }

    let secret = match job.role {
        Role::Helper(share) if job.seat < t && job.helpers[usize::from(job.seat)] == share.i => {
            Some(&share.x)
        }
        Role::Repairing(_) if job.seat == t => None,
        Role::Helper(_) | Role::Repairing(_) => return Err(Error::InvalidArgs),
    };

    Ok(Inputs {
        t,
        n_parties: t.checked_add(1).ok_or(Error::InvalidArgs)?,
        shared_public_key: &info.shared_public_key,
        public_shares: &info.public_shares,
        evaluation_points: &vss.I,
        #[cfg(feature = "hd-wallet")]
        chain_code: info.chain_code,
        secret,
    })
}

fn share_metadata<E: Curve>(job: &Job<'_, E>, inputs: &Inputs<'_, E>) -> ShareMetadata<E> {
    ShareMetadata {
        sid: job.sid.to_vec(),
        repairing: job.repairing,
        helpers: job.helpers.to_vec(),
        shared_public_key: *inputs.shared_public_key,
        public_shares: inputs.public_shares.to_vec(),
        evaluation_points: inputs.evaluation_points.to_vec(),
        threshold: inputs.t,
        #[cfg(feature = "hd-wallet")]
        chain_code: inputs.chain_code,
    }
}

fn metadata_matches<E: Curve>(
    job: &Job<'_, E>,
    inputs: &Inputs<'_, E>,
    round2: &RoundMsgs<MsgRound2<E>>,
) -> Result<(), Error> {
    let local = share_metadata(job, inputs);
    for (sender, _msg_id, msg) in round2.iter_indexed() {
        if sender >= inputs.t {
            continue;
        }
        match &msg.metadata {
            Some(metadata) if metadata == &local => {}
            _ => return Err(Error::MetadataMismatch),
        }
    }
    Ok(())
}

fn sample_pads<E, R>(rng: &mut R, seat: u16, t: u16) -> Vec<Scalar<E>>
where
    E: Curve,
    R: RngCore,
{
    if seat >= t {
        return Vec::new();
    }
    let count = usize::from(t - 1 - seat);
    (0..count).map(|_| Scalar::random(rng)).collect()
}

/// Pad carried from helper seat `sender` to seat `recipient`.
///
/// Outgoing pads are stored in recipient order, skipping every edge that
/// does not go to a later helper.
fn pad_on_edge<E: Curve>(
    sender: u16,
    recipient: u16,
    t: u16,
    outgoing_pads: &[Scalar<E>],
) -> Option<Scalar<E>> {
    if sender >= t || recipient >= t || recipient <= sender {
        return None;
    }
    let index = usize::from(recipient - sender - 1);
    outgoing_pads.get(index).copied()
}

fn helper_sigma<E: Curve>(
    job: &Job<'_, E>,
    inputs: &Inputs<'_, E>,
    outgoing_pads: &[Scalar<E>],
    round1: &RoundMsgs<MsgRound1<E>>,
) -> Result<Scalar<E>, Error> {
    let secret = inputs.secret.ok_or(Error::InvalidArgs)?;
    let helper_points = job
        .helpers
        .iter()
        .map(|helper| inputs.evaluation_points[usize::from(*helper)])
        .collect::<Vec<_>>();
    let at = *inputs.evaluation_points[usize::from(job.repairing)].as_ref();
    let zeta = lagrange_coefficient(at, usize::from(job.seat), &helper_points)
        .ok_or(Error::InvalidArgs)?;
    let x: &Scalar<E> = AsRef::<Scalar<E>>::as_ref(secret);
    let lambda = *zeta.as_ref() * *x;
    let diagonal = lambda - outgoing_pads.iter().copied().sum::<Scalar<E>>();

    let mut sigma = diagonal;
    for (sender, _msg_id, msg) in round1.iter_indexed() {
        if sender >= job.seat {
            continue;
        }
        let pad = msg.pad.ok_or(Error::MissingPad)?;
        sigma += pad;
    }

    #[cfg(test)]
    if job.corrupt_sigma {
        sigma += Scalar::one();
    }

    Ok(sigma)
}

fn accept_share<E: Curve>(
    inputs: &Inputs<'_, E>,
    repairing: u16,
    round2: &RoundMsgs<MsgRound2<E>>,
) -> Result<Option<NonZero<SecretScalar<E>>>, Error> {
    let mut sum = Scalar::<E>::zero();
    for (sender, _msg_id, msg) in round2.iter_indexed() {
        if sender >= inputs.t {
            continue;
        }
        let sigma = msg.sigma.ok_or(Error::MissingSigma)?;
        sum += sigma;
    }

    let mut wide = sum;
    let secret = SecretScalar::new(&mut wide);
    let restored = NonZero::from_secret_scalar(secret).ok_or(Error::BadReconstruction)?;
    let public = &inputs.public_shares[usize::from(repairing)];
    if *public != Point::generator() * &restored {
        return Err(Error::BadReconstruction);
    }
    Ok(Some(restored))
}

async fn send_to_others<E, S>(
    outgoings: &mut S,
    n_parties: u16,
    seat: u16,
    mut message: impl FnMut(u16) -> Msg<E>,
) -> Result<(), Error>
where
    E: Curve,
    S: futures_util::Sink<Outgoing<Msg<E>>> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    use futures_util::SinkExt;

    let messages = (0..n_parties)
        .filter(move |recipient| *recipient != seat)
        .map(|recipient| Ok(Outgoing::p2p(recipient, message(recipient))));
    outgoings
        .send_all(&mut futures_util::stream::iter(messages))
        .await
        .map_err(Error::send)
}

async fn exchange_round2<E, S, In, RecvErr>(
    outgoings: &mut S,
    rounds: &mut RoundsRouter<Msg<E>, In>,
    round2: round_based::rounds_router::Round<RoundInput<MsgRound2<E>>>,
    n_parties: u16,
    seat: u16,
    payload: Option<(Scalar<E>, ShareMetadata<E>)>,
) -> Result<RoundMsgs<MsgRound2<E>>, Error>
where
    E: Curve,
    S: futures_util::Sink<Outgoing<Msg<E>>> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
    In: futures_util::Stream<Item = Result<round_based::Incoming<Msg<E>>, RecvErr>> + Unpin,
    RecvErr: std::error::Error + Send + Sync + 'static,
{
    let repairing_seat = n_parties - 1;
    let mut payload = payload;
    send_to_others(outgoings, n_parties, seat, |recipient| {
        let (sigma, metadata) = if recipient == repairing_seat {
            payload.take().map_or((None, None), |(sigma, metadata)| {
                (Some(sigma), Some(metadata))
            })
        } else {
            (None, None)
        };
        Msg::Round2(MsgRound2 { sigma, metadata })
    })
    .await?;
    rounds.complete(round2).await.map_err(Error::receive)
}

#[cfg(test)]
mod tests {
    use generic_ec::curves::Secp256k1;
    use generic_ec::{NonZero, Point, Scalar};
    use key_share::{CoreKeyShare, DirtyKeyInfo};

    use super::{Error, Job, Role};

    fn dealer(threshold: Option<u16>, n: u16, hd: bool) -> Vec<CoreKeyShare<Secp256k1>> {
        let mut rng = rand::thread_rng();
        let builder = key_share::trusted_dealer::builder::<Secp256k1>(n).set_threshold(threshold);
        #[cfg(feature = "hd-wallet")]
        let builder = builder.hd_wallet(hd);
        #[cfg(not(feature = "hd-wallet"))]
        let _ = hd;
        builder.generate_shares(&mut rng).unwrap()
    }

    fn run_repair(
        shares: &[CoreKeyShare<Secp256k1>],
        repairing: u16,
        helpers: &[u16],
        corrupt_seat: Option<u16>,
        repairing_info: Option<DirtyKeyInfo<Secp256k1>>,
    ) -> Vec<Result<Option<NonZero<generic_ec::SecretScalar<Secp256k1>>>, Error>> {
        let n_parties = u16::try_from(helpers.len()).unwrap() + 1;
        round_based::sim::run(n_parties, |seat, party| {
            let shares = shares.to_vec();
            let helpers = helpers.to_vec();
            let repairing_info = repairing_info.clone();
            async move {
                let mut rng = rand::thread_rng();
                let role = if usize::from(seat) == helpers.len() {
                    Role::Repairing(
                        repairing_info
                            .as_ref()
                            .unwrap_or(&shares[usize::from(repairing)].key_info),
                    )
                } else {
                    Role::Helper(&shares[usize::from(helpers[usize::from(seat)])])
                };
                super::run(
                    &mut rng,
                    party,
                    Job {
                        sid: b"repair-test",
                        seat,
                        repairing,
                        helpers: &helpers,
                        role,
                        corrupt_sigma: corrupt_seat == Some(seat),
                    },
                )
                .await
            }
        })
        .unwrap()
        .into_vec()
    }

    #[test]
    fn restores_the_lost_share() {
        // Helper sets are not `0..t-1`, so a seat is not the key-share index.
        check_restores(2, 3, 0, &[1, 2]);
        check_restores(3, 5, 1, &[0, 2, 4]);
    }

    fn check_restores(t: u16, n: u16, repairing: u16, helpers: &[u16]) {
        let shares = dealer(Some(t), n, false);
        let before: Vec<_> = shares
            .iter()
            .map(|share| {
                (
                    *AsRef::<Scalar<Secp256k1>>::as_ref(&share.x),
                    share.shared_public_key,
                    share.public_shares.clone(),
                    share.vss_setup.as_ref().unwrap().I.clone(),
                )
            })
            .collect();

        let output = run_repair(&shares, repairing, helpers, None, None);
        let pr = usize::from(t);
        let restored = match &output[pr] {
            Ok(Some(share)) => share,
            other => panic!("repairing party failed: {other:?}"),
        };
        assert_eq!(
            AsRef::<Scalar<Secp256k1>>::as_ref(restored),
            &before[usize::from(repairing)].0
        );
        assert!(output[..pr].iter().all(|result| matches!(result, Ok(None))));

        for (share, (secret, public_key, public_shares, points)) in shares.iter().zip(&before) {
            assert_eq!(AsRef::<Scalar<Secp256k1>>::as_ref(&share.x), secret);
            assert_eq!(share.shared_public_key, *public_key);
            assert_eq!(&share.public_shares, public_shares);
            assert_eq!(&share.vss_setup.as_ref().unwrap().I, points);
        }
    }

    #[test]
    fn metadata_mismatch_rejects_the_repairing_party() {
        let shares = dealer(Some(3), 5, false);
        let helpers = [0u16, 2, 4];
        let mut info = shares[1].key_info.clone();
        let shifted =
            NonZero::from_point(Point::<Secp256k1>::generator() + *info.public_shares[0].as_ref())
                .unwrap();
        info.public_shares[0] = shifted;

        let output = run_repair(&shares, 1, &helpers, None, Some(info));
        assert!(output[..3].iter().all(|result| matches!(result, Ok(None))));
        assert!(matches!(output[3], Err(Error::MetadataMismatch)));
    }

    #[test]
    fn corrupt_sigma_fails_the_public_share_check() {
        let shares = dealer(Some(2), 3, false);
        let helpers = [1u16, 2];
        let output = run_repair(&shares, 0, &helpers, Some(0), None);
        assert!(matches!(output[0], Ok(None)));
        assert!(matches!(output[1], Ok(None)));
        assert!(matches!(output[2], Err(Error::BadReconstruction)));
    }

    #[test]
    fn rejects_inputs_the_protocol_cannot_run() {
        let additive = dealer(None, 3, false);
        assert!(matches!(
            validate_one(&additive, 0, 0, &[1, 2]),
            Err(Error::InvalidArgs)
        ));

        let shares = dealer(Some(3), 5, false);
        assert!(matches!(
            validate_one(&shares, 1, 1, &[0, 1, 2]),
            Err(Error::InvalidArgs)
        ));
        assert!(matches!(
            validate_one(&shares, 0, 1, &[0, 2]),
            Err(Error::InvalidArgs)
        ));

        let full = dealer(Some(3), 3, false);
        assert!(matches!(
            validate_one(&full, 0, 0, &[1, 2, 0]),
            Err(Error::InvalidArgs)
        ));
    }

    #[cfg(feature = "hd-wallet")]
    #[test]
    fn chain_code_is_part_of_the_share_metadata() {
        let shares = dealer(Some(2), 3, true);
        assert!(shares[0].chain_code.is_some());
        let helpers = [1u16, 2];
        let output = run_repair(&shares, 0, &helpers, None, None);
        assert!(matches!(output[2], Ok(Some(_))));

        let mut info = shares[0].key_info.clone();
        info.chain_code = Some([0x11; 32]);
        let output = run_repair(&shares, 0, &helpers, None, Some(info));
        assert!(matches!(output[0], Ok(None)));
        assert!(matches!(output[1], Ok(None)));
        assert!(matches!(output[2], Err(Error::MetadataMismatch)));
    }

    fn validate_one<'a>(
        shares: &'a [CoreKeyShare<Secp256k1>],
        seat: u16,
        repairing: u16,
        helpers: &'a [u16],
    ) -> Result<super::Inputs<'a, Secp256k1>, Error> {
        super::validate(&Job {
            sid: b"repair-test",
            seat,
            repairing,
            helpers,
            role: if usize::from(seat) == helpers.len() {
                Role::Repairing(&shares[usize::from(repairing)].key_info)
            } else {
                Role::Helper(&shares[usize::from(helpers[usize::from(seat)])])
            },
            corrupt_sigma: false,
        })
    }
}
