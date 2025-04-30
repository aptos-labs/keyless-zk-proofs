# Hashing notes

WARNING: Some of these algorithms are used in the keyless TXN validation logic on-chain
on Aptos. Changing them haphazardly will break backwards compatibility, so exercise
caution!

## Preliminaries

Let $\mathbb{F}$ denote circom's finite field of prime order $p$.
Let $B$ denote the number of bytes that can be fit into an element of $\mathbb{F}$ (e.g., $B = 31$ for BN254).
Let $H_n : \mathbb{F}^n -> \mathbb{F}$ (e.g., Poseidon) denote a hash function family.

This file implements templates for hashing various objects (byte arrays, strings, etc.), using $\mathbb{F}$ and $H_n$ as building blocks.

## Zero-padding

```
 ZeroPad_{max}(b) => pb:
  - (b_1, ..., b_n) <- b
  - pb <- (b_1, ..., b_n, 0, ... , 0) s.t. |pb| = max
```

Zero-pads an array of `n` bytes `b = [b_1, ..., b_n]` up to `max` bytes.

## Packing bytes to scalar(s)

```
 PackBytesToScalars_{max}(b) => (e_1, e_2, \ldots, e_k)
```

Packs $n$ bytes into $k = \lcei n/B \rceil$ field elements, zero-padding the last element
when $B$ does not divide $n$. Since circom fields will typically be prime-order, even
after fitting max $B$ bytes into a field element, we may be left with some extra
unused *bits* at the end. This function always sets those bits to zero!

WARNING: Not injective, since when there is room in a field element, we pad
it with zero bytes.
This is fine for our purposes, because we either hash length-suffixed byte arrays
or null-terminated strings. So the non-injectiveness of this can accounted for.
(Note to self: EPK *is* packed via this but its length in bytes is appended.)

TODO(Docs): Continue
