// copyright@ (2023) blackshirt
// This modules provides Elliptic Curve Diffie-Hellman (ECDHE) used by
// Key Exchange Protocol, commonly used by cryptography protocol.
// Currently only Curve25519 based is supported through x25519 function.
module curve25519

import sync
import crypto.rand
import crypto.internal.subtle

// Basically, Curve is a TLS 1.3 NamedGroup.
// its defined here for simplicity.
// vfmt off
pub enum Curve {
	secp256r1 = 0x0017
	secp384r1 = 0x0018
	secp521r1 = 0x0019
	x25519    = 0x001D
	x448      = 0x001E
	ffdhe2048 = 0x0100
	ffdhe3072 = 0x0101
	ffdhe4096 = 0x0102
	ffdhe6144 = 0x0103
	ffdhe8192 = 0x0104
}
// vfmt on

// new_key_exchanger creates new KeyExchanger for curve c,
// for this time, only curve25519 is supported
pub fn new_key_exchanger(c Curve) !KeyExchanger {
	match c {
		.x25519 { return new_x25519_key_exchanger() }
		else { return error("unsupported curve") }
	}
}

// This const for Curve25519 based curve
pub const (
	key_size         = 32
	private_key_size = key_size
	public_key_size  = key_size
)

// Key Exchange Protocol
pub interface KeyExchanger {
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

// PublicKey represent public keys
struct PublicKey {
	curve  KeyExchanger
	pubkey []u8
}

// equal tell if two PublicKey is equal, its check if has the same curve and its also check
// if underlying pubkey bytes has exactly the same length and contents.
pub fn (pk PublicKey) equal(x PublicKey) bool {
	return pk.curve == x.curve && pk.pubkey.len == x.pubkey.len
		&& subtle.constant_time_compare(pk.pubkey, x.pubkey) == 1
}

// bytes returns bytes content of PublicKey.
pub fn (pk PublicKey) bytes() ![]u8 {
	if pk.pubkey.len != pk.curve.public_key_size() {
		return error('pubkey.len does not math with curve pubkey size')
	}
	mut buf := []u8{len: pk.curve.public_key_size()}
	_ := copy(mut buf, pk.pubkey)
	return buf
}

// PrivateKey represent private keys. Its stores PublicKey here for minor enhancement.
// its not recommended to access it directly, but call `.public_key()` instead to get PublicKey part.
// and, its not made as a public, if you wanto to have to create it, you should create its from KeyExchanger instance,
// and then call `.private_key_from_key` or `generate_private_key` instead.
struct PrivateKey {
	curve   KeyExchanger
	privkey []u8
mut:
	pubk      PublicKey
	pubk_once sync.Once = sync.new_once()
}

// bytes return PrivateKey as a bytes array
pub fn (pv PrivateKey) bytes() ![]u8 {
	if pv.privkey.len != pv.curve.private_key_size() {
		return error('privkey.len does not match with curve privatekey size')
	}
	mut buf := []u8{len: pv.curve.private_key_size()}
	_ := copy(mut buf, pv.privkey)
	return buf
}

// equal whether two PrivateKey has equally identical (its not check pubkey part)
pub fn (pv PrivateKey) equal(oth PrivateKey) bool {
	return pv.curve == oth.curve && pv.privkey.len == oth.privkey.len
		&& subtle.constant_time_compare(pv.privkey, oth.privkey) == 1
}

pub fn (mut prv PrivateKey) public_key() !PublicKey {
	prv.pubk_once.do_with_param(fn (mut o PrivateKey) {
		// internal pubkey of privatekey does not initialized to some values
		// TODO: more good check
		if o.pubk.pubkey.len != o.curve.public_key_size() {
			// we can not return error here, so panic instead.
			opk := o.curve.public_key(o) or { panic(err) }
			o.pubk = opk
		} else {
			pk := PublicKey{
				curve: o.curve
				pubkey: o.pubk.pubkey
			}
			o.pubk = pk
		}
	}, prv)
	return prv.pubk
}

// Curve25519 ecdh protocol
struct Ecdh25519 {}

fn (ec Ecdh25519) str() string {
	return 'Ecdh25519'
}

// new_x25519_key_exchanger creates new Curve25519 based ECDH key exchange protocol
pub fn new_x25519_key_exchanger() KeyExchanger {
	return Ecdh25519{}
}

// private_key_size returns private key size, in bytes
pub fn (ec Ecdh25519) private_key_size() int {
	return curve25519.private_key_size
}

// public_key_size returns public key size, in bytes
pub fn (ec Ecdh25519) public_key_size() int {
	return curve25519.public_key_size
}

// private_key_from_key generates PrivateKey from seeded key.
pub fn (ec Ecdh25519) private_key_from_key(key []u8) !PrivateKey {
	if key.len != curve25519.private_key_size {
		return error('Wrong key len')
	}
	// we dont clamping here
	privk := PrivateKey{
		curve: ec
		privkey: key
	}

	return privk
}

// generate_private_key generates PrivateKey with random entropy using `crypto.rand`
pub fn (ec Ecdh25519) generate_private_key() !PrivateKey {
	privkey := rand.read(curve25519.private_key_size)!
	privk := ec.private_key_from_key(privkey)!
	return privk
}

// privkey_to_pubkey calculates PublicKey part of given PrivateKey
fn (ec Ecdh25519) privkey_to_pubkey(prv PrivateKey) !PublicKey {
	if prv.privkey.len != curve25519.private_key_size {
		return error('Wrong privkey len')
	}
	pubkey := x25519(prv.privkey, base_point)!

	pubk := PublicKey{
		curve: ec
		pubkey: pubkey
	}

	return pubk
}

// public_key gets PublicKey part of PrivateKey
pub fn (ec Ecdh25519) public_key(pv PrivateKey) !PublicKey {
	pk := ec.privkey_to_pubkey(pv)!
	return pk
}

// shared_secret computes shared keys between two parties, alice private keys and others public keys.
// Its commonly used as elliptic curve diffie-hellman (ECDH) key exchange protocol
pub fn (ec Ecdh25519) shared_secret(local PrivateKey, remote PublicKey) ![]u8 {
	if local.privkey.len != curve25519.private_key_size
		|| remote.pubkey.len != curve25519.public_key_size {
		return error('Wrong local len or remote len')
	}
	secret := x25519(local.privkey, remote.pubkey)!
	if is_zero(secret) {
		return error('secret result zeroed')
	}
	return secret
}

// is_zero returns whether seed is all zeroes in constant time.
fn is_zero(seed []u8) bool {
	mut acc := u8(0)
	for b in seed {
		acc |= b
	}
	return acc == 0
}
