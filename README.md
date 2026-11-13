# Threshold key repair

- [Specification](#specification)
- [Running the protocol](#running-the-protocol)
  - [Networking](#networking)
  - [Session identifier](#session-identifier)
  - [Participants](#participants)
  - [What one run exchanges](#what-one-run-exchanges)
- [HD wallets](#hd-wallets)
- [Building](#building)
- [Join us in Discord!](#join-us-in-discord)

Threshold key repair restores one lost Shamir share of an existing $t$-out-of-$n$ key. The polynomial, the joint public key, the other secret shares, and the public shares stay as they were. The party who lost the share receives the same $x_r = f(I(r))$ it held before.

[Laing–Stinson] is a survey of repairable threshold schemes. This protocol is their triangular pad scheme ([§4.1.3](https://eprint.iacr.org/2017/1155)). Each helper sends the public description of the repair with its $\sigma$. The repairing party accepts the share only when every helper sent the same description. Any $t$ holders of the key can be the helpers. The repairing party does not need a key-share record. A coordinator supplies the public key data before Round 1.

Refresh is a separate protocol. It adds a zero-sharing onto a share the party already holds, so it needs $x_r$. If the missing share may have been copied, repair comes first. Threshold key refresh runs afterwards, once all $n$ parties hold a share again.

This repository holds the specification and a Rust implementation. The implementation uses the same [`round-based`] delivery model as [cggmp24]. The entry point is crate-private and is exercised by the tests. There is no published API yet.

## Specification

[`spec/key-repair.tex`](spec/key-repair.tex) is the protocol definition.

```bash
cd spec
pdflatex key-repair.tex
```

CI compiles the same file. On a pull request it comments with a link to the PDF.

## Running the protocol

The repair session has exactly $t + 1$ parties: the repairing party and $t$ helpers. The key has $n$ signers, with $2 \le t \le n - 1$, and any $t$ holders can be the helpers. Additive $n$-out-of-$n$ shares have no polynomial to interpolate, so they are outside this protocol.

### Networking

Parties communicate through a stream of incoming messages and a sink of outgoing messages:

```rust
let incoming: impl Stream<Item = Result<Incoming<Msg>>>;
let outgoing: impl Sink<Outgoing<Msg>>;

let delivery = (incoming, outgoing);
let party = round_based::MpcParty::connected(delivery);
```

`Msg` is the repair message type. It is crate-private, so this is the shape the tests use. `round_based::Incoming` and `round_based::Outgoing` add the sender and the recipient. The concrete network (libp2p, a delivery server, a database) is up to the application. The protocol only requires:

* Every message is authenticated. The receiver checks that the message comes from the claimed sender.
* Every point-to-point message is encrypted. Only the designated recipient can read a pad or a $\sigma$.

Pads and $\sigma$ values are plain scalars. Confidentiality is the channel. A wrong pad makes the repairing party's check $x_r \cdot G = X_r$ fail. The protocol does not name which helper to blame.

### Session identifier

Every participant agrees on a session identifier `sid`: a byte string that identifies this key and this repair, and that is assumed never to repeat. It is part of the share metadata, so a message from another repair does not match.

### Participants

Two kinds of index show up, and they are not the same number.

The **key-share index** is the index stored in the key share. It lies in $0 \le i < n$. The missing share has index $r$. The helper set $\mathcal{H}$ has size $t$, does not contain $r$, and is written in increasing key-share index. Every participant must share this numbering. With a public key per signer, sorting those keys and taking each signer's position is one way to assign it.

The **seat** is the `round-based` party index for this run only. Seats `0..t-1` are the helpers in increasing key-share index. Seat `t` is the repairing party. That order is the triangle order. It is not written into the evaluation points $I$, and it does not change any party's key-share index. A helper's seat is not its key-share index.

Each helper inputs its key share: the secret $x_h$, the joint public key $Y$, the public shares $X$, the evaluation points $I$, the threshold $t$, and $n$. The repairing party inputs the same public record, with no secret share. A coordinator (or any helper) gives it $(Y, X, I, t, n)$ before Round 1. With the `hd-wallet` feature, that record also includes the chain code.

The repairing party accepts the result only when $x_r \cdot G = X_r$, and stores $x_r$ next to the public data at index $r$. Helpers finish with no new share. $X$, $Y$, $I$, $t$, $n$, the chain code, and every helper's secret stay unchanged.

Paillier auxiliary data is not part of the restored share. A repairing party that lost it with $x_r$ has to run auxiliary-data generation again with all $n$ parties before it can presign.

### What one run exchanges

Round 1. Each helper samples a random pad for every later helper and sends it. Those pads do not depend on the sender's share. The diagonal pad, which does depend on the share, stays local.

Round 2. Each helper sends its $\sigma$ and the share metadata to the repairing party. The metadata is `sid`, the missing index, the helper set, $Y$, $X$, $I$, $t$, and the chain code when HD wallets are on.

Round 3. The repairing party checks that every helper's metadata equals its own copy, sums the $\sigma$ values, and checks the result against $X_r$. Helpers do not perform that check.

## HD wallets

The `hd-wallet` feature includes the chain code in the share metadata. Every participant in the run has to be built with the same choice. A chain code on one side and a different chain code on the other makes the metadata disagree, and the repairing party rejects the share.

## Building

```bash
cargo test
cargo test --all-features
```

Tests build threshold shares with the `key-share` trusted dealer (`spof`, dev-dependency only) on secp256k1. `cargo test` covers a key with no chain code. `cargo test --all-features` also runs the HD-wallet case.

## License

MIT OR Apache-2.0

## Join us in Discord!

[in Discord](https://discord.com/invite/hyperledger)

[Laing–Stinson]: https://eprint.iacr.org/2017/1155
[cggmp24]: https://github.com/LFDT-Lockness/cggmp21
[`round-based`]: https://docs.rs/round-based
