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

It can be used in a preprocessing 2-round FROST scheme, although I haven't
specifically designed any of the APIs for this use-case.

## Warnings

* This **has not been audited in any way**, use at your own risk.
* For technical reasons, we only support up to 254 parties at once.

## Options

* `debug_eprintlns` to print out group debugging information when doing signing operatioins
