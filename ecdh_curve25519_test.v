module curve25519

import crypto.hmac
import encoding.hex

fn test_x25519_ecdh() ! {
	dh := new_key_exchanger()

	priv_bob := []u8{len: 32}
	mut secret := []u8{len: 32}

	for i := 0; i < 2; i++ {
		priv_alice, pub_alice := dh.generate_key_pair()!
		pub_bob := dh.public_key(priv_bob)!

		sec_alice := dh.shared_secret(priv_alice, pub_bob)!
		sec_bob := dh.shared_secret(priv_bob, pub_alice)!

		assert hmac.equal(sec_alice, sec_bob) == true
		assert hmac.equal(secret, sec_alice) == false
		copy(mut secret, sec_alice)
	}
}

const (
	// Test vector from https://tools.ietf.org/html/rfc7748#section-6.1
	alice_privkey = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
	alice_pubkey  = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
	bob_privkey   = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
	bob_pubkey    = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
	shared_secret = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
)

fn test_generate_key() ! {
	dh := new_key_exchanger()

	for i := 0; i < 50; i++ {
		our_privkey, our_pubkey := dh.generate_key_pair()!
		their_privkey, their_pubkey := dh.generate_key_pair()!

		s1 := dh.shared_secret(our_privkey, their_pubkey)!
		s2 := dh.shared_secret(their_privkey, our_pubkey)!

		assert hmac.equal(s1, s2) == true
		assert hmac.equal(our_pubkey, dh.public_key(our_privkey)!)
		assert hmac.equal(their_pubkey, dh.public_key(their_privkey)!)
	}
}

fn test_from_rfc_vectors_key() ! {
	dh := new_key_exchanger()

	alice_privbytes := hex.decode(curve25519.alice_privkey)!

	ask, apk := dh.keypair_from_bytes(alice_privbytes)!

	alice_pk := dh.public_key(ask)!
	assert hmac.equal(apk, alice_pk)

	assert curve25519.alice_pubkey == hex.encode(apk[..])

	bskhex := hex.decode(curve25519.bob_privkey)!

	bsk, bpk := dh.keypair_from_bytes(bskhex)!

	assert curve25519.bob_pubkey == hex.encode(bpk[..])

	s1 := dh.shared_secret(ask, bpk)!
	s2 := dh.shared_secret(bsk, apk)!

	assert hmac.equal(s1, s2) == true

	assert hex.encode(s1) == curve25519.shared_secret
}
