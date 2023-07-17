module curve25519

import crypto.rand

pub const (
	// key_size is the size of PublicKey and PrivateKey in bytes
	key_size = 32
)

// PublicKey represent public keys
pub type PublicKey = []u8

// PrivateKey represent private keys
pub type PrivateKey = []u8

pub interface KeyExchanger {
	// generate_key_pair generates private public key pair using entropy from `crypto.rand`
	generate_key_pair() !(PrivateKey, PublicKey)
	// keypair_from_bytes generates private public key pair from seeded seed
	keypair_from_bytes(seed []u8) !(PrivateKey, PublicKey)
	// params returns underlying curve parameters
	params() Params
	// public_key returns public key corresponding private key
	public_key(PrivateKey) !PublicKey
	// TODO: perform check on public key results
	// check(peer PublicKey) bool
	// shared_secret computes shared secret between alice privkey and bob's public key
	shared_secret(privkey PrivateKey, otherpubkey PublicKey) ![]u8
}

// Params tell underlying curve parameters
pub struct Params {
	name     string
	bit_size int
}

struct ECDH25519 {
	name     string
	bit_size int
}

//  new_key_exchanger creates new ECDH key exchange protocol backed by Curve25519
pub fn new_key_exchanger() KeyExchanger {
	return ECDH25519{
		name: 'Curve25519'
		bit_size: 255
	}
}

// keypair_from_bytes generates private public key pair from seeded bytes.
pub fn (e ECDH25519) keypair_from_bytes(seed []u8) !(PrivateKey, PublicKey) {
	if seed.len != curve25519.key_size {
		return error('Wrong seed len')
	}
	mut privkey := seed.clone()
	// do clamping
	privkey[0] &= 248
	privkey[31] &= 127
	privkey[31] |= 64

	pubkey := x25519(privkey, basepoint)!

	return PrivateKey(privkey), PublicKey(pubkey)
}

// generate_key_pair generates private and public key pair with random entropy using `crypto.rand`
pub fn (e ECDH25519) generate_key_pair() !(PrivateKey, PublicKey) {
	mut privkey := rand.read(curve25519.key_size)!

	// we do clamping here
	privkey[0] &= 248
	privkey[31] &= 127
	privkey[31] |= 64

	pubkey := x25519(privkey, basepoint)!

	return PrivateKey(privkey), PublicKey(pubkey)
}

// params return underlying curve parameters.
pub fn (e ECDH25519) params() Params {
	return Params{
		name: e.name
		bit_size: e.bit_size
	}
}

// public_key calculates public key part of privkey
pub fn (e ECDH25519) public_key(privkey PrivateKey) !PublicKey {
	if privkey.len != curve25519.key_size {
		return error('Wrong privkey len')
	}
	pubkey := x25519(privkey, basepoint)!

	return PublicKey(pubkey)
}

// shared_secret computes shared keys between two parties, alice private keys and others public keys.
// Its commonly used as elliptic curve diffie-hellman (ECDH) key exchange protocol
//
pub fn (e ECDH25519) shared_secret(privkey PrivateKey, otherspub PublicKey) ![]u8 {
	if privkey.len != curve25519.key_size || otherspub.len != curve25519.key_size {
		return error('Wrong privkey len or otherspub len')
	}
	secret := x25519(privkey, otherspub)!

	return secret
}
