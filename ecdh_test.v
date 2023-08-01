module curve25519

import crypto.hmac
import encoding.hex

fn test_x25519_ecdh() ! {
	dh := new_x25519_key_exchanger()

	mut privkey_bob := dh.private_key_from_key([]u8{len: 32})!
	mut secret := []u8{len: 32}

	for i := 0; i < 2; i++ {
		mut privkey_alice := dh.generate_private_key()!
		pubkey_alice := dh.public_key(privkey_alice)!
		pubkey_bob := dh.public_key(privkey_bob)!

		sec_alice := dh.shared_secret(privkey_alice, pubkey_bob)!
		sec_bob := dh.shared_secret(privkey_bob, pubkey_alice)!

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
	dh := new_x25519_key_exchanger()

	for i := 0; i < 50; i++ {
		our_privkey := dh.generate_private_key()!
		our_pubkey := dh.public_key(our_privkey)!
		their_privkey := dh.generate_private_key()!
		their_pubkey := dh.public_key(their_privkey)!

		s1 := dh.shared_secret(our_privkey, their_pubkey)!
		s2 := dh.shared_secret(their_privkey, our_pubkey)!

		assert hmac.equal(s1, s2) == true
		assert our_pubkey.equal(dh.public_key(our_privkey)!)
		assert their_pubkey.equal(dh.public_key(their_privkey)!)
	}
}

fn test_from_rfc_vectors_key() ! {
	dh := new_x25519_key_exchanger()

	alice_privbytes := hex.decode(curve25519.alice_privkey)!

	ask := dh.private_key_from_key(alice_privbytes)!
	apk := dh.public_key(ask)!

	alice_pk := dh.public_key(ask)!
	assert apk.equal(alice_pk)

	assert curve25519.alice_pubkey == hex.encode(apk.pubkey[..])

	bskhex := hex.decode(curve25519.bob_privkey)!

	bsk := dh.private_key_from_key(bskhex)!
	bpk := dh.public_key(bsk)!
	assert curve25519.bob_pubkey == hex.encode(bpk.pubkey[..])

	s1 := dh.shared_secret(ask, bpk)!
	s2 := dh.shared_secret(bsk, apk)!

	assert hmac.equal(s1, s2) == true

	assert hex.encode(s1) == curve25519.shared_secret
}
