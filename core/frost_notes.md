# FROST notes

This doc was created while trying to troubleshoot the generation of the
commitment message being inconsistent in rounds 1 and 2 of the keygen process.

* `g` - generator
* `ScalarBaseMult(scalar)` - `g * scalar`
* `e.MulAdd(x, y)` - `e * y + z` mod p (scalars) (for secp256k1's field this is just implemented as `.Mul` and `.Add` separately)

## Round 1 process

```
s <- random scalar
ki <- random scalar
Ri = ScalarBaseMult(ki)
ci = hash_to_field(..., Ri)
wi = s.MulAdd(ci, ki) = s * ci + ki
```

Then `wi` gets passed to another party in round 2 as `bcast[id].wi`.

## Round 2 process

```
Aj0 = bcast[id].Verifiers.Commitments[0]
prod1 = ScalarBaseMult(bcast[id].wi)
prod2 = Aj0 * bcast[id].Ci^-1
prod = prod1 + prod2
cj = hash_to_field(..., prod)
```

Then `prod` here should exactly match the `ci` from above.
