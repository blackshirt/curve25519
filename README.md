# curve25519
-----------

This module provides unctionality `x25519` function, which performs scalar multiplication on the elliptic curve known as Curve25519.

## About curve25519

From wikipedia, Curve25519 is an elliptic curve used in elliptic-curve cryptography (ECC) offering 128 bits of security (256-bit key size) and designed for use with the elliptic curve Diffie–Hellman (ECDH) key agreement scheme. It is one of the fastest curves in ECC, and is not covered by any known patents. The reference implementation is public domain software. The original Curve25519 paper defined it as a Diffie–Hellman (DH) function. Daniel J. Bernstein has since proposed that the name "Curve25519" be used for the underlying curve, and the name "X25519" for the DH function Curve25519 is an elliptic curve that offers 128 security bits and is designed for use in the Elliptic Curve Diffie-Hellman (ECDH) key agreement key design scheme.

## Installation
```bash
v install https://github.com/blackshirt/curve25519
```

## Contents
- [Constants](#Constants)
- [x25519](#x25519)


## Constants
```v
const (
	// scalar_size is the size of the scalar to the x25519
	scalar_size = 32

	// point_size is the size of the point input to the x25519
	point_size  = 32

	// zero_point is point with 32 bytes of zero  (null) bytes
	zero_point  = []u8{len: 32, cap: 32, init: u8(0x00)}

	// base_point is the canonical Curve25519 generator, encoded as a byte with value 9,
	// followed by 31 zero bytes
	base_point  = [u8(9), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0]
)
```

## x25519
```v
fn x25519(scalar []u8, point []u8) ![]u8
```

x25519 returns the result of the scalar multiplication (scalar * point), according to RFC 7748, Section 5. scalar, point and the return value are
slices of 32 bytes.  
The functions take a scalar and a u-coordinate as inputs and produce a u-coordinate as output.  
Although the functions work internally with integers, the inputs and outputs are 32-byte strings (for X25519) scalar can be generated at random, for example with `crypto.rand` and point should
be either base_point or the output of another `x25519` call.  

