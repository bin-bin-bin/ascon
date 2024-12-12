#include "ascon.h"

int _string_to_uint64_t(const char str[8], uint64_t *num) {
    if (!num) return -1;
    *num = 0;
	for (int8_t i = 0; i < 8; i++) {
		*num <<= 8;
		*num |= (uint8_t)str[i];
	}
	return 0;
}

int _uint64_t_to_string(uint64_t num, char str[8]) {
    if (!str) return -1;
    for (int i = 0; i < 8; i++) {
        str[7 - i] = num & 0xFF;
        num >>= 8;
    }
    return 0;
}

/* Ascon AEAD encryption procedure.
 * Paratemters:
 * 	- inter_r: round number for intermediate processes
 *  - bsize: rate size
 * 	- k: key in an ascon_key instance
 * 	- n: nonce in an ascon_nonce instance
 * 	- alen: length of associated data
 * 	- len: length of the payload
 * 	- a: pointer to the associated data
 * 	- p: pointer to the payload
 * 	- t: pointer to the tag
 * Return: int
 *  - 0 if successful, non-zero if error
 */
int ascon_aead_encrypt(ascon_r inter_r, ascon_rate_size bsize, ascon_key *k, ascon_nonce *n, size_t alen, size_t len, const char *a, char *p, char *t) {
	if (!k || !n || !t) return -1;
	if (alen && !a) return -1;
	if (len && !p) return -1;

	ascon_state state;
	ascon_tag tag;

	if (ascon_aead_state_init(&state, bsize, inter_r, k, n)) return -2;
	if (ascon_aead_assoc_data_proc(&state, bsize, inter_r, alen, a)) return -3;

	if (ascon_aead_payload_proc(&state, bsize, inter_r, len, p, outmode_out)) return -4;

	if (ascon_aead_state_fin(&state, bsize, k, &tag)) return -5;

	if (_uint64_t_to_string(tag.high, t)) return -6;
	if (_uint64_t_to_string(tag.low, t + 8)) return -6;

	return 0;
}

/* Ascon AEAD decryption procedure.
 * Paratemters:
 * 	- inter_r: round number for intermediate processes
 *  - bsize: rate size
 * 	- k: key in an ascon_key instance
 * 	- n: nonce in an ascon_nonce instance
 * 	- t: tag in an ascon_tag instance
 * 	- len: length of the payload
 * 	- a: pointer to the associated data
 * 	- p: pointer to the payload
 * Return: int
 *  - 0 if successful, non-zero if error
 */
int ascon_aead_decrypt(ascon_r inter_r, ascon_rate_size bsize, ascon_key *k, ascon_nonce *n, ascon_tag *t, size_t alen, size_t len, const char *a, char *p) {
	if (!k || !n || !t) return -1;
	if (alen && !a) return -1;
	if (len && !p) return -1;

	ascon_state state;
	ascon_tag tag;

	if (ascon_aead_state_init(&state, bsize, inter_r, k, n)) return -2;
	if (ascon_aead_assoc_data_proc(&state, bsize, inter_r, alen, a)) return -3;

	if (ascon_aead_payload_proc(&state, bsize, inter_r, len, p, outmode_swap)) return -4;

	if (ascon_aead_state_fin(&state, bsize, k, &tag)) return -5;
	if (tag.high != t->high || tag.low != t->low) return -5;

	return 0;
}

int ascon_128a_encrypt(const char key[16], const char nonce[16],
						 size_t assoc_len, const char *assoc_data,
						 size_t len,       char *payload,
						 char *tag) {
	ascon_r inter_r = _8_rounds;
	ascon_rate_size bsize = _128bit_rate;
	ascon_key _key;
	ascon_nonce _nonce;

	if (_string_to_uint64_t(key, &_key.high)) return -7;
	if (_string_to_uint64_t(key + 8, &_key.low)) return -7;
	if (_string_to_uint64_t(nonce, &_nonce.high)) return -7;
	if (_string_to_uint64_t(nonce + 8, &_nonce.low)) return -7;

	return ascon_aead_encrypt(inter_r, bsize, &_key, &_nonce, assoc_len, len, assoc_data, payload, tag);
}

int ascon_128a_decrypt(const char key[16], const char nonce[16], const char tag[16],
						 size_t assoc_len, const char *assoc_data,
						 size_t len,       char *payload) {
	ascon_r inter_r = _8_rounds;
	ascon_rate_size bsize = _128bit_rate;
	ascon_key _key;
	ascon_nonce _nonce;
	ascon_tag _tag;

	if (_string_to_uint64_t(key, &_key.high)) return -7;
	if (_string_to_uint64_t(key + 8, &_key.low)) return -7;
	if (_string_to_uint64_t(nonce, &_nonce.high)) return -7;
	if (_string_to_uint64_t(nonce + 8, &_nonce.low)) return -7;
	if (_string_to_uint64_t(tag, &_tag.high)) return -7;
	if (_string_to_uint64_t(tag + 8, &_tag.low)) return -7;

	return ascon_aead_decrypt(inter_r, bsize, &_key, &_nonce, &_tag, assoc_len, len, assoc_data, payload);
}
