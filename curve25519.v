module curve25519

import crypto.internal.subtle
import crypto.ed25519.internal.edwards25519

pub const (
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

// x25519 returns the result of the scalar multiplication (scalar * point),
// according to RFC 7748, Section 5. scalar, point and the return value are
// slices of 32 bytes.
// The functions take a scalar and a u-coordinate as inputs and produce a u-coordinate as output.
// Although the functions work internally with integers, the inputs and
// outputs are 32-byte strings (for X25519)
// scalar can be generated at random, for example with `crypto.rand` and point should
// be either base_point or the output of another `x25519` call.
pub fn x25519(scalar []u8, point []u8) ![]u8 {
	mut dst := []u8{len: 32, cap: 32}
	return x25519_generic(mut dst, scalar, point)
}

fn x25519_generic(mut dst []u8, scalar []u8, point []u8) ![]u8 {
	if scalar.len != curve25519.scalar_size {
		return error('bad scalar length: ${scalar.len}')
	}
	if point.len != curve25519.point_size {
		return error('bad point length: ${point.len}')
	}

	inp := scalar.clone()

	if point == curve25519.base_point {
		// check_basepoint()
		scalar_base_mult(mut dst, inp)!
	} else {
		base := point.clone()
		scalar_mult(mut dst, inp, base)!
		if subtle.constant_time_compare(dst[..], curve25519.zero_point) == 1 {
			return error('bad input point: low order point')
		}
	}
	return dst
}

fn scalar_base_mult(mut dst []u8, scalar []u8) ! {
	scalar_mult(mut dst, scalar, curve25519.base_point)!
}

fn scalar_mult(mut dst []u8, scalar []u8, point []u8) ! {
	if scalar.len != curve25519.scalar_size {
		return error('scalar.lenght != 32')
	}
	if point.len != curve25519.point_size {
		return error('point.lenght != 32')
	}

	// This has been checked above, its safe, so scalar.len == 32
	mut e := scalar.clone()

	// According to RFC 7748, for x25519, in order to decode 32 random bytes
	// as an integer scalar, set the three least significant bits of the first byte
	// and the most significant bit of the last to zero,
	// set the second most significant bit of the last byte to 1
	//
	// so, we do bytes clamping here
	e[0] &= 248
	e[31] &= 127
	e[31] |= 64

	mut x1 := edwards25519.Element{}
	mut x2 := edwards25519.Element{}
	mut z2 := edwards25519.Element{}
	mut x3 := edwards25519.Element{}
	mut z3 := edwards25519.Element{}
	mut tmp0 := edwards25519.Element{}
	mut tmp1 := edwards25519.Element{}

	x1.set_bytes(point[..])!
	x2.one()
	x3.set(x1)
	z3.one()

	mut swap := 0
	for pos := 254; pos >= 0; pos-- {
		mut b := e[pos / 8] >> u32(pos & 7)
		b &= 1
		swap = swap ^ int(b)
		x2.swap(mut x3, swap)
		z2.swap(mut z3, swap)
		swap = int(b)

		tmp0.subtract(x3, z3)
		tmp1.subtract(x2, z2)
		x2.add(x2, z2)
		z2.add(x3, z3)
		z3.multiply(tmp0, x2)
		z2.multiply(z2, tmp1)
		tmp0.square(tmp1)
		tmp1.square(x2)
		x3.add(z3, z2)
		z2.subtract(z3, z2)
		x2.multiply(tmp1, tmp0)
		tmp1.subtract(tmp1, tmp0)
		z2.square(z2)

		z3.mult_32(tmp1, 121666)
		x3.square(x3)
		tmp0.add(tmp0, z3)
		z3.multiply(x1, z2)
		z2.multiply(tmp1, tmp0)
	}

	x2.swap(mut x3, swap)
	z2.swap(mut z3, swap)

	z2.invert(z2)
	x2.multiply(x2, z2)
	copy(mut dst, x2.bytes())
}

// this is not needed, we don't have global var
/*
fn check_basepoint() {
	eq := subtle.constant_time_compare(base_point, [u8(0x09), 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
	if eq != 1 {
		panic('curve25519: global asepoint value was modified')
	}
}
*/
