#include <vector>
#include <assert.h>
#include "include/secp256k1.h"


static constexpr unsigned int SIGNATURE_SIZE = 72;
static secp256k1_context* secp256k1_context_sign = nullptr;
static constexpr unsigned int PUBLIC_KEY_SIZE = 65;
static constexpr unsigned int COMPRESSED_PUBLIC_KEY_SIZE = 33;
static const unsigned int PRIVATE_KEY_SIZE = 279;
static const unsigned int COMPRESSED_PRIVATE_KEY_SIZE = 214;

void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
	uint32_t v = x;
	memcpy(ptr, (char*)& v, 4);
}

bool SigHasLowR(const secp256k1_ecdsa_signature* sig)
{
	unsigned char compact_sig[64];
	secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_sign, compact_sig, sig);

	// In DER serialization, all values are interpreted as big-endian, signed integers. The highest bit in the integer indicates
	// its signed-ness; 0 is positive, 1 is negative. When the value is interpreted as a negative integer, it must be converted
	// to a positive value by prepending a 0x00 byte so that the highest bit is 0. We can avoid this prepending by ensuring that
	// our highest bit is always 0, and thus we must check that the first byte is less than 0x80.
	return compact_sig[0] < 0x80;
}

static int ec_privkey_export_der(const secp256k1_context* ctx, unsigned char* privkey, size_t* privkeylen, const unsigned char* key32, bool compressed) {
	assert(*privkeylen >= PRIVATE_KEY_SIZE);
	secp256k1_pubkey pubkey;
	size_t pubkeylen = 0;
	if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
		*privkeylen = 0;
		return 0;
	}
	if (compressed) {
		static const unsigned char begin[] = {
			0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
		};
		static const unsigned char middle[] = {
			0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
			0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
			0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
			0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
			0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
			0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
		};
		unsigned char* ptr = privkey;
		memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
		memcpy(ptr, key32, 32); ptr += 32;
		memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
		pubkeylen = COMPRESSED_PUBLIC_KEY_SIZE;
		secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
		ptr += pubkeylen;
		*privkeylen = ptr - privkey;
		assert(*privkeylen == COMPRESSED_PRIVATE_KEY_SIZE);
	}
	else {
		static const unsigned char begin[] = {
			0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
		};
		static const unsigned char middle[] = {
			0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
			0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
			0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
			0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
			0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
			0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
			0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
			0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
		};
		unsigned char* ptr = privkey;
		memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
		memcpy(ptr, key32, 32); ptr += 32;
		memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
		pubkeylen = PUBLIC_KEY_SIZE;
		secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
		ptr += pubkeylen;
		*privkeylen = ptr - privkey;
		assert(*privkeylen == PRIVATE_KEY_SIZE);
	}
	return 1;
}


static int ecdsa_signature_parse_der_lax(const secp256k1_context * ctx, secp256k1_ecdsa_signature * sig, const unsigned char* input, size_t inputlen) {
	size_t rpos, rlen, spos, slen;
	size_t pos = 0;
	size_t lenbyte;
	unsigned char tmpsig[64] = { 0 };
	int overflow = 0;

	/* Hack to initialize sig with a correctly-parsed but invalid signature. */
	secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

	/* Sequence tag byte */
	if (pos == inputlen || input[pos] != 0x30) {
		return 0;
	}
	pos++;

	/* Sequence length bytes */
	if (pos == inputlen) {
		return 0;
	}
	lenbyte = input[pos++];
	if (lenbyte & 0x80) {
		lenbyte -= 0x80;
		if (lenbyte > inputlen - pos) {
			return 0;
		}
		pos += lenbyte;
	}

	/* Integer tag byte for R */
	if (pos == inputlen || input[pos] != 0x02) {
		return 0;
	}
	pos++;

	/* Integer length for R */
	if (pos == inputlen) {
		return 0;
	}
	lenbyte = input[pos++];
	if (lenbyte & 0x80) {
		lenbyte -= 0x80;
		if (lenbyte > inputlen - pos) {
			return 0;
		}
		while (lenbyte > 0 && input[pos] == 0) {
			pos++;
			lenbyte--;
		}
		static_assert(sizeof(size_t) >= 4, "size_t too small");
		if (lenbyte >= 4) {
			return 0;
		}
		rlen = 0;
		while (lenbyte > 0) {
			rlen = (rlen << 8) + input[pos];
			pos++;
			lenbyte--;
		}
	}
	else {
		rlen = lenbyte;
	}
	if (rlen > inputlen - pos) {
		return 0;
	}
	rpos = pos;
	pos += rlen;

	/* Integer tag byte for S */
	if (pos == inputlen || input[pos] != 0x02) {
		return 0;
	}
	pos++;

	/* Integer length for S */
	if (pos == inputlen) {
		return 0;
	}
	lenbyte = input[pos++];
	if (lenbyte & 0x80) {
		lenbyte -= 0x80;
		if (lenbyte > inputlen - pos) {
			return 0;
		}
		while (lenbyte > 0 && input[pos] == 0) {
			pos++;
			lenbyte--;
		}
		static_assert(sizeof(size_t) >= 4, "size_t too small");
		if (lenbyte >= 4) {
			return 0;
		}
		slen = 0;
		while (lenbyte > 0) {
			slen = (slen << 8) + input[pos];
			pos++;
			lenbyte--;
		}
	}
	else {
		slen = lenbyte;
	}
	if (slen > inputlen - pos) {
		return 0;
	}
	spos = pos;

	/* Ignore leading zeroes in R */
	while (rlen > 0 && input[rpos] == 0) {
		rlen--;
		rpos++;
	}
	/* Copy R value */
	if (rlen > 32) {
		overflow = 1;
	}
	else {
		memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
	}

	/* Ignore leading zeroes in S */
	while (slen > 0 && input[spos] == 0) {
		slen--;
		spos++;
	}
	/* Copy S value */
	if (slen > 32) {
		overflow = 1;
	}
	else {
		memcpy(tmpsig + 64 - slen, input + spos, slen);
	}

	if (!overflow) {
		overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
	}
	if (overflow) {
		/* Overwrite the result again with a correctly-parsed but invalid
		   signature if parsing failed. */
		memset(tmpsig, 0, 64);
		secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
	}
	return 1;
}


int main()
{
	//init
	secp256k1_context* secp256k1_context_sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	assert(secp256k1_context_sign != nullptr);
	{
		// Pass in a random blinding seed to the secp256k1 context, 32 bytes
		unsigned char random_seed[] = { 1,6,8,7,5,6,4,9,8,7,5,6,2,1,0,2,5,4,7,8,6,2,1,5,2,3,5,7,2,5,1,2 };
		bool ret = secp256k1_context_randomize(secp256k1_context_sign, random_seed);
		assert(ret);
	}

	uint8_t secret_key[32] = { 41,51,71,51,61,71,61,21,71,31,11,31,111,56,84,91,51,781,61,71,61,51,48,81,61,46,87,81,61,87,69,100 };
	auto is_valid = secp256k1_ec_seckey_verify(secp256k1_context_sign, secret_key);

	
	secp256k1_pubkey pubkey;
	int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, secret_key);
	std::vector<unsigned char> public_key;
	{
		//public key
		size_t clen = PUBLIC_KEY_SIZE;
		assert(ret);
		public_key.resize(PUBLIC_KEY_SIZE);
		secp256k1_ec_pubkey_serialize(secp256k1_context_sign, public_key.data(), &clen, &pubkey, SECP256K1_EC_COMPRESSED);
		assert(COMPRESSED_PUBLIC_KEY_SIZE == clen);
		public_key.resize(COMPRESSED_PUBLIC_KEY_SIZE);
	}
	{
		//private key
		std::vector<unsigned char> private_key;
		private_key.resize(PRIVATE_KEY_SIZE);
		size_t privkeylen = PRIVATE_KEY_SIZE;
		ret = ec_privkey_export_der(secp256k1_context_sign, private_key.data(), &privkeylen, secret_key, true);
		assert(ret);
		assert(COMPRESSED_PRIVATE_KEY_SIZE == privkeylen);
		private_key.resize(COMPRESSED_PRIVATE_KEY_SIZE);
	}

	//signature
	std::vector<unsigned char> vchSig;
	vchSig.resize(SIGNATURE_SIZE);
	size_t nSigLen = SIGNATURE_SIZE;
	unsigned char extra_entropy[32] = { 0 };
	WriteLE32(extra_entropy, 0);
	secp256k1_ecdsa_signature sig;
	uint8_t msg_hash[] = { 4,5,7,5,6,7,6,2,7,3,1,3,111,56,84,9,5,78,6,7,6,5,48,8,6,46,87,8,61,87,69,100 };
	ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, msg_hash, secret_key, secp256k1_nonce_function_rfc6979, nullptr);
	// Grind for low R
	uint32_t counter = 0;
	while (ret && !SigHasLowR(&sig)) {
		WriteLE32(extra_entropy, ++counter);
		ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, msg_hash, secret_key, secp256k1_nonce_function_rfc6979, extra_entropy);
	}
	assert(ret);
	secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, vchSig.data(), &nSigLen, &sig);
	vchSig.resize(nSigLen);


	//confirm
	auto secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	assert(secp256k1_context_verify != nullptr);
	secp256k1_pubkey pubkey299;
	secp256k1_ecdsa_signature sig300;
	if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey299, public_key.data(), public_key.size())) {
		return false;
	}
	if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig300, vchSig.data(), vchSig.size())) {
		return false;
	}
	/* libsecp256k1's ECDSA verification requires signatures, which have
	 * not historically been enforced in Bitcoin, so normalize them first. */
	secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig300, &sig300);
	auto ok = secp256k1_ecdsa_verify(secp256k1_context_verify, &sig300, msg_hash, &pubkey299);

	secp256k1_context_destroy(secp256k1_context_verify);
	secp256k1_context_destroy(secp256k1_context_sign);
	return 0;
}