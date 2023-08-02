module curve25519

import crypto.hmac
import encoding.hex

fn test_x25519_key_exchanger() ! {
	// this data from https://tls13.xargs.org/#server-key-exchange-generation
	client_privkey := hex.decode('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')!
	client_pubkey := hex.decode('358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254')!
	client_shared_secret := hex.decode('df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624')!

	server_privkey := hex.decode('909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')!
	server_pubkey := hex.decode('9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615')!
	server_shared_secret := hex.decode('df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624')!

	kx := new_x25519_key_exchanger()
	mut client_prvkey := kx.private_key_from_key(client_privkey)!

	// calculates PublicKey from private key with sync.do
	pubk_sync := client_prvkey.public_key()!

	server_prvkey := kx.private_key_from_key(server_privkey)!
	// PublicKey part of the private key
	server_pubk := kx.public_key(server_prvkey)!

	// PublicKey part of the private key
	client_pubk := kx.public_key(client_prvkey)!

	// test wheter client PublicKey generated from Key
	assert client_pubk.equal(pubk_sync)

	// assert if PublicKey result is expected
	assert client_pubk.bytes()! == client_pubkey

	// compute shared_secret between client private key and server public key
	calc_client_shared := kx.shared_secret(client_prvkey, server_pubk)!
	assert client_shared_secret == calc_client_shared

	// assert if PublicKey result is expected
	assert server_pubk.bytes()! == server_pubkey

	// compute shared_secret between server private key and client public key
	calc_server_shared := kx.shared_secret(server_prvkey, client_pubk)!
	assert calc_server_shared == server_shared_secret

	// assert two shared secret is identical
	assert calc_client_shared == calc_server_shared
}

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
