#include "ascon_core.h"

uint64_t ascon_rconst[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
							 0x78, 0x69, 0x5a, 0x4b}; //round constants
#ifdef ASCON_IMP_LOOKUP_TABLE
uint8_t ascon_stable[0x20] = {0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2,
							  0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1c,
							  0x1e, 0x13, 0x7, 0xe, 0x0, 0xd, 0x11, 0x18,
							  0x10, 0xc, 0x1, 0x19, 0x16, 0xa, 0xf, 0x17}; //s-box lookup table
#endif

int _is_little_endian() {
	ascon_state state;
	state.row[0] = 1;
	return state.byte[0][0];
}

/* Constant addition step in the Ascon permutation.
 * Parameters:
 * - state: pre-allocated ascon_state instance
 * - rc: round count (starts from zero)
 * - r: round number (variant dependent)
 * Return: inline function returns void
 */
static inline void _ascon_permutation_c(ascon_state *state, uint8_t rc, uint8_t r) {
	uint8_t low = rc + 12 - r;
	uint8_t high = (15 - low) << 4;
	state->row[2] ^= low | high; //ascon_rconst[low];
}

/* Substitution layer in the Ascon permutation.
 * Parameters:
 * - state: pre-allocated ascon_state instance
 * Return: inline function returns void
 */
// === permutation_s implementation switch === //
//#define ASCON_IMP_LOOKUP_TABLE
#define ASCON_IMP_PARALLEL
//#define ASCON_IMP_PIPELINE
// ============================================= //
static inline void _ascon_permutation_s(ascon_state *state) {
#ifdef ASCON_IMP_LOOKUP_TABLE
	//implementation method: lookup table
    for (int8_t slice = 0; slice < 64; slice++) {
		uint8_t temp = 0;
		uint64_t rb = 1;
		rb <<= slice;
		for (int8_t row = 0; row < 5; row++) {
			if (state->row[row] & rb) temp |= 1 << (4 - row);
			state->row[row] &= ~rb;
		}
		temp = ascon_stable[temp];
		for (int8_t row = 0; row < 5; row++) {
			if (temp & (1 << (4 - row))) state->row[row] |= rb;
		}
	}
#endif
#ifdef ASCON_IMP_PARALLEL
	//implementation method: parallelizing
	uint64_t *row = state->row, temp_row[5];
    temp_row[0] = row[3] ^ row[4] ^ (row[1] | row[0] ^ row[2] ^ row[4]),
    temp_row[1] = row[0] ^ row[4] ^ (row[1] ^ row[2] | row[2] ^ row[3]),
    temp_row[2] = row[1] ^ row[2] ^ (row[3] | ~row[4]),
    temp_row[3] = row[1] ^ row[2] ^ (row[0] | row[3] ^ row[4]),
    temp_row[4] = row[3] ^ row[4] ^ (row[1] & ~(row[0] ^ row[4]));
    for (int8_t i = 0; i < 5; i++) state->row[i] = temp_row[i];
#endif
#ifdef ASCON_IMP_PIPELINE
	//implementation method: pipelining (from 7.2 "Flexibility of the Permutation")
	state->row[0] ^= state->row[4];
	state->row[4] ^= state->row[3];
	state->row[2] ^= state->row[1];
	uint64_t temp_row[5];
	for (int8_t i = 0; i < 5; i++) temp_row[i] = ~state->row[i] & state->row[(i + 1) % 5];
	for (int8_t i = 0; i < 5; i++) state->row[i] ^= temp_row[(i + 1) % 5];
	state->row[1] ^= state->row[0];
	state->row[0] ^= state->row[4];
	state->row[3] ^= state->row[2];
	state->row[2] = ~state->row[2];
#endif
}

/* Linear diffusion layer in the Ascon permutation.
 * Parameters:
 * - state: pre-allocated ascon_state instance
 * Return: inline function returns void
 */
static inline void _ascon_permutation_l(ascon_state *state) {
	state->row[0] ^= (state->row[0] >> 19 | state->row[0] << 45) ^ (state->row[0] >> 28 | state->row[0] << 36);
	state->row[1] ^= (state->row[1] >> 61 | state->row[1] <<  3) ^ (state->row[1] >> 39 | state->row[1] << 25);
	state->row[2] ^= (state->row[2] >>  1 | state->row[2] << 63) ^ (state->row[2] >>  6 | state->row[2] << 58);
	state->row[3] ^= (state->row[3] >> 10 | state->row[3] << 54) ^ (state->row[3] >> 17 | state->row[3] << 47);
	state->row[4] ^= (state->row[4] >>  7 | state->row[4] << 57) ^ (state->row[4] >> 41 | state->row[4] << 23);
}

/* The Ascon permutation.
 * Parameters:
 * - state: pre-allocated ascon_state instance
 * - r: number of rounds to perform the permutation.
 * Return: int
 *  - 0 if successful, non-zero if error
 */
int ascon_permutation(ascon_state *state, ascon_r r) {
	if (!state) return -1;
	for (int8_t i = 0; i < r; i++) {
		_ascon_permutation_c(state, i, r);
		_ascon_permutation_s(state);
		_ascon_permutation_l(state);
	}
	return 0;
}

/* Payload processing for Ascon AEAD
 * Parameters:
 * - state: pre-allocated ascon_state instance
 * - bsize: rate size
 * - inter_r: round number for intermediate processes (variant dependent)
 * - len: length in bytes of payload data
 * - payload: actual payload
 * - outmode: indicate whether to write outer part of the state back to the payload
 * |- outmode_none: no output performed. payload will stay intact after procedure
 * |- outmode_out: each byte of the payload will be replaced with corresponding byte in the state
 * |- outmode_swap: each byte of the payload will be swapped with corresponding byte in the state
 * Return: int
 *  - 0 if successful, non-zero if error
 */
int ascon_aead_payload_proc(ascon_state *state, ascon_rate_size bsize, ascon_r inter_r, size_t len, char *payload, ascon_aead_payload_proc_outmode outmode) {
	if (!state) return -1;
	if (len && !payload) return -1;

	uint8_t pmask = ~(~0 << (2 + bsize / 64)), //4 bits for 128-bit rate, 3 bits for 64-bit rate
			lemask = _is_little_endian() * 7, row = 0, col = lemask;
	for (char *pos = payload, pb = 0; pos < payload + len; pos++,
		 pb = (pos - payload) & pmask, col = (pb & 7) ^ lemask, row = pb >> 3) {
		//xor payload block with rate of the state
		if (outmode == outmode_swap) *pos ^= state->byte[row][col];
		state->byte[row][col] ^= *pos;
		if (outmode == outmode_out) *pos = state->byte[row][col];

		//intermediate permutation to the state
		if (pb == pmask && ascon_permutation(state, inter_r)) return -1;
	}
	//padding
	state->byte[row][col] ^= 0x80;

	return 0;
}

/* Associated data process of Ascon AEAD
 * Parameters:
 *  - state: initialized ascon_state instance
 *  - bsize: rate size
 * 	- inter_r: round number for intermediate processes
 *  - len: length in bytes of associated data
 *  - payload: actual payload of associated data
 * Return: int
 *  - 0 if successful, non-zero if error
 */
int ascon_aead_assoc_data_proc(ascon_state *state, ascon_rate_size bsize, ascon_r inter_r, size_t len, const char *payload) {
	if (!state) return -1;
	if (len && !payload) return -1;

	if (len > 0) {
		ascon_aead_payload_proc(state, bsize, inter_r, len, (char *const)payload, outmode_none);
		if (ascon_permutation(state, inter_r)) return -1;
	}

	//xor domain separation constant
	state->row[4] ^= 1;

	return 0;
}

/* State initialization for Ascon AEAD
 * Parameters:
 * 	- state: pre-allocated ascon_state instance
 *  - bsize: rate size
 * 	- inter_r: round number for intermediate processes
 * 	- key: pre-allocated ascon_key instance
 * 	- nonce: pre-allocated ascon_nonce instance
 * Return: int
 *  - 0 if successful, non-zero if error
 */
int ascon_aead_state_init(ascon_state *state, ascon_rate_size bsize, ascon_r inter_r, ascon_key *key, ascon_nonce *nonce) {
	if (!state || !key || !nonce) return -1;

	memset(state, 0, sizeof(ascon_state));

	//iv filling
	uint8_t lemask = _is_little_endian() * 7;
	char iv_args[] = {
		128,		//key size is 128
		bsize,		//rate size
		_12_rounds,	//round number in finalization
		inter_r		//round number in intermediate processes
	};
	for (uint8_t i = 0; i < 4; i++) state->byte[0][i ^ lemask] = iv_args[i];

	//key filling
	state->row[1] = key->high;
	state->row[2] = key->low;

	//nonce filling
	state->row[3] = nonce->high;
	state->row[4] = nonce->low;

	//initial round transformation
	if (ascon_permutation(state, _12_rounds)) return -1;

	//xor with 0*||K
	state->row[3] ^= key->high;
	state->row[4] ^= key->low;

	return 0;
}

/* Finalization of Ascon AEAD
 * Parameters:
 * 	- state: pre-allocated ascon_state instance
 *  - bsize: rate size
 * 	- key: pre-allocated ascon_key instance
 * 	- tag: pre-allocated ascon_tag instance
 * Return: int
 *  - 0 if successful, non-zero if error
 */
int ascon_aead_state_fin(ascon_state *state, ascon_rate_size bsize, ascon_key *key, ascon_tag *tag) {
	if (!state || !key || !tag) return -1;

	//xor with 0_r||K||0_c-k
	uint8_t row = bsize / 64;
	state->row[row] ^= key->high;
	state->row[row + 1] ^= key->low;

	//finalizing round transformation
	if (ascon_permutation(state, _12_rounds)) return -1;

	//output tag
	tag->high = state->row[3] ^ key->high;
	tag->low = state->row[4] ^ key->low;

	return 0;
}
