/* SPDX-License-Identifier: ISC
 *
 * AWG 3.1 header protection. Linux AWG uses crypto/chacha.h with an
 * initial counter of zero and the first 12 bytes of S1..S4 as the IETF
 * ChaCha20 nonce. This file implements the same primitive locally so the
 * FreeBSD port does not depend on a private/raw kernel ChaCha API.
 */
#include <sys/param.h>
#include <sys/endian.h>
#include <sys/systm.h>

#include "header_protection.h"

static inline uint32_t
rotl32(uint32_t v, unsigned int n)
{
	return ((v << n) | (v >> (32 - n)));
}

#define QR(a, b, c, d) do { \
	(a) += (b); (d) ^= (a); (d) = rotl32((d), 16); \
	(c) += (d); (b) ^= (c); (b) = rotl32((b), 12); \
	(a) += (b); (d) ^= (a); (d) = rotl32((d), 8);  \
	(c) += (d); (b) ^= (c); (b) = rotl32((b), 7);  \
} while (0)

static void
awg_chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
    uint32_t counter, uint8_t out[64])
{
	uint32_t s[16], x[16];
	static const uint32_t constants[4] = {
		0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U
	};

	s[0] = constants[0]; s[1] = constants[1];
	s[2] = constants[2]; s[3] = constants[3];
	for (int i = 0; i < 8; i++)
		s[4 + i] = le32dec(key + i * 4);
	s[12] = counter;
	s[13] = le32dec(nonce + 0);
	s[14] = le32dec(nonce + 4);
	s[15] = le32dec(nonce + 8);
	memcpy(x, s, sizeof(x));

	for (int i = 0; i < 10; i++) {
		QR(x[0], x[4], x[8],  x[12]);
		QR(x[1], x[5], x[9],  x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);
		QR(x[0], x[5], x[10], x[15]);
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[8],  x[13]);
		QR(x[3], x[4], x[9],  x[14]);
	}
	for (int i = 0; i < 16; i++)
		le32enc(out + i * 4, x[i] + s[i]);
	explicit_bzero(s, sizeof(s));
	explicit_bzero(x, sizeof(x));
}

static void
awg_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
    uint8_t *buf, size_t len)
{
	uint8_t block[64];
	uint32_t counter = 0;
	while (len != 0) {
		size_t n = MIN(len, sizeof(block));
		awg_chacha20_block(key, nonce, counter++, block);
		for (size_t i = 0; i < n; i++)
			buf[i] ^= block[i];
		buf += n;
		len -= n;
	}
	explicit_bzero(block, sizeof(block));
}

bool
awg_header_protection_selftest(void)
{
    static const uint8_t expected_zero[64] = {
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
        0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
        0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
        0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
    };
    static const uint8_t expected_rfc[64] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    };
    uint8_t key[32] = { 0 };
    uint8_t nonce[12] = { 0 };
    uint8_t stream[128] = { 0 };
    bool ok;

    awg_chacha20_xor(key, nonce, stream, 64);
    ok = timingsafe_bcmp(stream, expected_zero, 64) == 0;

    for (size_t i = 0; i < sizeof(key); i++)
        key[i] = (uint8_t)i;

    static const uint8_t rfc_nonce[12] = {
        0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    memcpy(nonce, rfc_nonce, sizeof(nonce));
    explicit_bzero(stream, sizeof(stream));

    awg_chacha20_xor(key, nonce, stream, sizeof(stream));
    ok = ok &&
        timingsafe_bcmp(stream + 64, expected_rfc, 64) == 0;

    explicit_bzero(stream, sizeof(stream));
    explicit_bzero(key, sizeof(key));
    explicit_bzero(nonce, sizeof(nonce));

    return (ok);
}

void
awg_header_protection_snapshot(struct awg_header_protection *hp,
    struct awg_hp_snapshot *snapshot)
{
        rw_rlock(&hp->hp_lock);
        snapshot->enabled = hp->hp_has_protection;
        memcpy(snapshot->key, hp->hp_key, sizeof(snapshot->key));
        rw_runlock(&hp->hp_lock);
}

void
awg_header_protection_crypt_snapshot(const struct awg_hp_snapshot *snapshot,
    const uint8_t nonce[AWG_HEADER_PROTECTION_NONCE_SIZE],
    uint8_t *buf, size_t len)
{
        if (!snapshot->enabled)
                return;

        awg_chacha20_xor(snapshot->key, nonce, buf, len);
}

void
awg_header_protection_init(struct awg_header_protection *hp)
{
	rw_init(&hp->hp_lock, "awg header protection");
	explicit_bzero(hp->hp_key, sizeof(hp->hp_key));
	hp->hp_has_protection = false;
}

void
awg_header_protection_destroy(struct awg_header_protection *hp)
{
	rw_wlock(&hp->hp_lock);
	explicit_bzero(hp->hp_key, sizeof(hp->hp_key));
	hp->hp_has_protection = false;
	rw_wunlock(&hp->hp_lock);
	rw_destroy(&hp->hp_lock);
}

bool
awg_header_protection_enabled(struct awg_header_protection *hp)
{
	bool enabled;
	rw_rlock(&hp->hp_lock);
	enabled = hp->hp_has_protection;
	rw_runlock(&hp->hp_lock);
	return (enabled);
}

void
awg_header_protection_set_key(struct awg_header_protection *hp, const uint8_t *key)
{
	uint8_t nonzero = 0;

	for (size_t i = 0; i < AWG_HEADER_PROTECTION_KEY_SIZE; i++)
		nonzero |= key[i];

	rw_wlock(&hp->hp_lock);
	explicit_bzero(hp->hp_key, sizeof(hp->hp_key));
	if (nonzero != 0)
		memcpy(hp->hp_key, key, sizeof(hp->hp_key));
	hp->hp_has_protection = (nonzero != 0);
	rw_wunlock(&hp->hp_lock);
}

void
awg_header_protection_get_key(struct awg_header_protection *hp, uint8_t *key)
{
	rw_rlock(&hp->hp_lock);
	memcpy(key, hp->hp_key, sizeof(hp->hp_key));
	rw_runlock(&hp->hp_lock);
}

void
awg_header_protection_crypt(struct awg_header_protection *hp,
    const uint8_t nonce[AWG_HEADER_PROTECTION_NONCE_SIZE], uint8_t *buf, size_t len)
{
	uint8_t key[AWG_HEADER_PROTECTION_KEY_SIZE];

	rw_rlock(&hp->hp_lock);
	if (!hp->hp_has_protection) {
		rw_runlock(&hp->hp_lock);
		return;
	}
	memcpy(key, hp->hp_key, sizeof(key));
	rw_runlock(&hp->hp_lock);

	awg_chacha20_xor(key, nonce, buf, len);
	explicit_bzero(key, sizeof(key));
}
