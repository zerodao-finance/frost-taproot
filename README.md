# frost-taproot

This is an implementation of [FROST](https://eprint.iacr.org/2020/852) in a
3-round aggregatorless scheme.  It does not rely on a central signature
aggregator, but assumes there is some reliable broadcast mechanism.  All parties
involved play some part of the aggregator role.

**Of note**, this implemtation is specifically designed to produce BIP340 sigs,
for use in Taproot, which is what Bitcoin uses for schnorr signature.  This
comes with a few benefits, mainly in producing round 32 byte pubkeys and 64 byte
signatures.

This is based on the implemetation Coinbase's
[kryptology](https://github.com/coinbase/kryptology) has in Go, but refactored
to be more Rustic and generate signatures in the correct way we want.

It can be used in a preprocessing 2-round FROST scheme, although the APIs
haven't been specifically designed for this use-case.

## Warnings

* This **has not been audited in any way**, use at your own risk.
* For technical reasons, we only support up to 254 parties at once.

## Options

* `debug_eprintlns` to print out group debugging information when doing signing operatioins

## Usage

Various data types are parametric on an instance of a `Math` trait.  This was
designed to faciliate eventually being able to use the crate for more curves
than just secp256k1 in the future, but right now the only instance is the
`Secp256k1Math` type.

Most types are serializable with serde, so that is what is currently
reccomended, although in the near future there will be more compact
binary representations of the state and message types.

Errors include participant IDs of relevant parties in cases of fraud.  Mapping
global party identifiers to local participant IDs is unspecified, implement this
in whichever way is convenient.  Participant IDs as passed to the algorithms
must start at 1.

**See `src/frost/test.rs` for full usage scenarios.**

### DKG

Initialize a DKG session participant by calling `dkg::InitParticipantState::new`.
It's assumed that participant IDs, thresholds, and other general parameters have
already been decided at this time.  There's also a paramter for an abitrary
`ctx` bytestring that's used in some commitments that should be pre-agreed-upon.

After initialization (probably immediately after), each participant performs the
first DKG step by sampling a random secret scalar value and invoking
`dkg::round_1` using the initial participant state, the secret, and providing
some randomness.  This step produces an `R1ParticipantState`, a broadcast
message that should be posted publicly, and a set of messages that should be
encrypted and sent to each other participent on some secure transport.

After all parties have published these messages, they can perform round 2.  They
do this by passing the R1 state, the broadcast messages from other peers, and
the decrypted p2p messages they received from other parties to `dkg::round_2`.
This produces a final `R2ParticipantState` and should emit a "broadcast"
message including the final Taproot pubkey.  The state returned should be
persisted securely, as this has our share of the multisig private key that's
necessary to participate in the threshold signing scheme.

The final pubkey can be extracted by `bcast.to_schnorr_pubkey().to_native()` and
probably would be presented to users as a standard `bc1p` Taproot address in practice.

### Threshold signing

To prepare for a threshold signing session, we must first decide the set of
participants that are going to be involved in the signing session.  We create a
signer instance by calling `thresh::SignerState::new` with the R2 state we
stored after the DKG process.  We also pass a `Bip340Chderiv` to use it with
Taproot.

The signer state types work slightly differently for the threshold signing
because it may be changed in the future for use in different round
configurations.

After initializing a signer instance, we perform round 1 by passing it with some
randomness to `thresh::round_1`.  This produces a new state and a broadcast
message.  (This includes the `D_i` and `E_i` commitments from the FROST paper.)

After all parties receive the expected commitments from above we can proceed to
round 2.  It may be necessary to change the API slightly to only decide on the
list of cosigners at this point, since only at this point do we need to decide
on the list of cosigners.  At this point we must also decide on the message to
be signed, hashed.  All of this information is provided to `thresh::round_2`,
producing a new state and another broadcast message.

After all the round 2 broadcast messages have been published, each party then
passes their states with the messages to `thresh::round_3` to produce a final
signed state and the signature.  It is verified internally before this function
returns, so it should always be valid.

The signature in a standard representation can be extracted from the round 3
broadcast message with `bcast.to_taproot_sig().to_native()` and should be able
to be verified with any standard BIP340-compliant library.
