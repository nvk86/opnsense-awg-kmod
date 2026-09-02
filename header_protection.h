/* SPDX-License-Identifier: ISC
 * AWG 3.1 ChaCha20 header protection for FreeBSD.
 */
#ifndef _AWG_HEADER_PROTECTION_H_
#define _AWG_HEADER_PROTECTION_H_

#include <sys/types.h>
#include <sys/rwlock.h>

#define AWG_HEADER_PROTECTION_KEY_SIZE 32
#define AWG_HEADER_PROTECTION_NONCE_SIZE 12

struct awg_header_protection {
	struct rwlock hp_lock;
	uint8_t hp_key[AWG_HEADER_PROTECTION_KEY_SIZE];
	bool hp_has_protection;
};

void awg_header_protection_init(struct awg_header_protection *);
void awg_header_protection_destroy(struct awg_header_protection *);
bool awg_header_protection_enabled(struct awg_header_protection *);
void awg_header_protection_set_key(struct awg_header_protection *, const uint8_t *);
void awg_header_protection_get_key(struct awg_header_protection *, uint8_t *);
void awg_header_protection_crypt(struct awg_header_protection *, const uint8_t *, uint8_t *, size_t);

#endif
