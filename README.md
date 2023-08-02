# module curve25519


# curve25519
----------

This module provides two functionality :

1. Provides x25519 function, which performs scalar multiplication on the elliptic curve known as Curve25519
2. Elliptic curve Diffie–Hellman (ECDH) key exchange protocol that allows two parties, each having an elliptic curve public–private key pair, to establish a shared secret over an insecure channel. Currently, its only support Curve25519.

## About curve25519

Curve25519 is an elliptic curve that offers 128 security bits and is designed for use in 
the Elliptic Curve Diffie-Hellman (ECDH) key agreement key design scheme.

## Installation
```bash
v install https://github.com/blackshirt/curve25519
```

## Contents
- [Constants](#Constants)
- [x25519](#x25519)
- [Curve](#Curve)
- [new_key_exchanger](#new_key_exchanger)
- [KeyExchanger](#KeyExchanger)
- [PublicKey](#PublicKey)
  - [equal](#equal)
  - [bytes](#bytes)
- [PrivateKey](#PrivateKey)
  - [bytes](#bytes)
  - [equal](#equal)
  - [public_key](#public_key)
- [new_x25519_key_exchanger](#new_x25519_key_exchanger)
- [Ecdh25519](#Ecdh25519)
  - [curve_id](#curve_id)
  - [private_key_size](#private_key_size)
  - [public_key_size](#public_key_size)
  - [private_key_from_key](#private_key_from_key)
  - [generate_private_key](#generate_private_key)
  - [public_key](#public_key)
  - [shared_secret](#shared_secret)
- [verify](#verify)

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


[[Return to contents]](#Contents)

```v
const (
	key_size         = 32
	private_key_size = key_size
	public_key_size  = key_size
)
```

This const for Curve25519 based curve

[[Return to contents]](#Contents)

## x25519
```v
fn x25519(scalar []u8, point []u8) ![]u8
```

x25519 returns the result of the scalar multiplication (scalar * point), according to RFC 7748, Section 5. scalar, point and the return value are
slices of 32 bytes.  
The functions take a scalar and a u-coordinate as inputs and produce a u-coordinate as output.  
Although the functions work internally with integers, the inputs and outputs are 32-byte strings (for X25519) scalar can be generated at random, for example with `crypto.rand` and point should
be either base_point or the output of another `x25519` call.  

[[Return to contents]](#Contents)

## Curve
```v
enum Curve {
	secp256r1 = 0x0017
	secp384r1 = 0x0018
	secp521r1 = 0x0019
	x25519 = 0x001D
	x448 = 0x001E
	ffdhe2048 = 0x0100
	ffdhe3072 = 0x0101
	ffdhe4096 = 0x0102
	ffdhe6144 = 0x0103
	ffdhe8192 = 0x0104
}
```

Basically, Curve is a TLS 1.3 NamedGroup.  
its defined here for simplicity.  
vfmt off

[[Return to contents]](#Contents)

## new_key_exchanger
```v
fn new_key_exchanger(c Curve) !KeyExchanger
```

new_key_exchanger creates new KeyExchanger for curve c, for this time, only curve25519 is supported

[[Return to contents]](#Contents)

## KeyExchanger
```v
interface KeyExchanger {
	// curve_id tell the curve id
	curve_id() Curve
	// private_key_size should return underlying PrivateKey bytes size.
	private_key_size() int
	// public_key_size should return underlying PublicKey bytes size.
	public_key_size() int
	// generate_private_key generates random PrivateKey using entropy from secure crypto random generator.
	generate_private_key() !PrivateKey
	// private_key_from_key generates PrivateKey from some given key.
	private_key_from_key(key []u8) !PrivateKey
	// public_key returns public key corresponding to PrivateKey.
	public_key(PrivateKey) !PublicKey
	// shared_secret computes shared secret between alice PrivateKey and bob's PublicKey.
	shared_secret(local PrivateKey, remote PublicKey) ![]u8
}
```

Key Exchange Protocol

[[Return to contents]](#Contents)

## PublicKey
## equal
```v
fn (pk PublicKey) equal(x PublicKey) bool
```

equal tell if two PublicKey is equal, its check if has the same curve and its also check
if underlying pubkey bytes has exactly the same length and contents.  

[[Return to contents]](#Contents)

## bytes
```v
fn (pk PublicKey) bytes() ![]u8
```

bytes returns bytes content of PublicKey.  

[[Return to contents]](#Contents)

## PrivateKey
## bytes
```v
fn (pv PrivateKey) bytes() ![]u8
```

bytes return PrivateKey as a bytes array

[[Return to contents]](#Contents)

## equal
```v
fn (pv PrivateKey) equal(oth PrivateKey) bool
```

equal whether two PrivateKey has equally identical (its not check pubkey part)

[[Return to contents]](#Contents)

## public_key
```v
fn (mut prv PrivateKey) public_key() !PublicKey
```

public_key is accessor for `privatekey.pubk` public key part, its does check if matching public key part or initializes PublicKey if not. Initialization is does under `sync.do_with_param`
to make sure its  that a function is executed only once.  

[[Return to contents]](#Contents)

## new_x25519_key_exchanger
```v
fn new_x25519_key_exchanger() KeyExchanger
```

new_x25519_key_exchanger creates new Curve25519 based ECDH key exchange protocol

[[Return to contents]](#Contents)

## Ecdh25519
## curve_id
```v
fn (ec Ecdh25519) curve_id() Curve
```

return underlying curve id

[[Return to contents]](#Contents)

## private_key_size
```v
fn (ec Ecdh25519) private_key_size() int
```

private_key_size returns private key size, in bytes

[[Return to contents]](#Contents)

## public_key_size
```v
fn (ec Ecdh25519) public_key_size() int
```

public_key_size returns public key size, in bytes

[[Return to contents]](#Contents)

## private_key_from_key
```v
fn (ec Ecdh25519) private_key_from_key(key []u8) !PrivateKey
```

private_key_from_key generates PrivateKey from seeded key.  

[[Return to contents]](#Contents)

## generate_private_key
```v
fn (ec Ecdh25519) generate_private_key() !PrivateKey
```

generate_private_key generates PrivateKey with random entropy using `crypto.rand`

[[Return to contents]](#Contents)

## public_key
```v
fn (ec Ecdh25519) public_key(pv PrivateKey) !PublicKey
```

public_key gets PublicKey part of PrivateKey

[[Return to contents]](#Contents)

## shared_secret
```v
fn (ec Ecdh25519) shared_secret(local PrivateKey, remote PublicKey) ![]u8
```

shared_secret computes shared keys between two parties, alice private keys and others public keys.  
Its commonly used as elliptic curve diffie-hellman (ECDH) key exchange protocol

[[Return to contents]](#Contents)

## verify
```v
fn verify(ec KeyExchanger, privkey PrivateKey, pubkey PublicKey) bool
```

given PrivateKey privkey, verify do check whether given PublicKey pubkey is really keypair for privkey. Its check by calculating public key part of
given PrivateKey.  

[[Return to contents]](#Contents)
