#ifndef ASCON_CORE_H_
#define ASCON_CORE_H_

#include <stdint.h>
#include <string.h>

typedef enum {
	_6_rounds = 6,
	_8_rounds = 8,
	_12_rounds = 12
} ascon_r; //round number

typedef enum {
	_64bit_rate = 64,
	_128bit_rate = 128
} ascon_rate_size;

typedef enum {
	outmode_none = 0,
	outmode_out = 1,
	outmode_swap = 2
} ascon_aead_payload_proc_outmode;

typedef union {
	uint64_t row[5];
	uint8_t byte[5][8]; //for ease of access; care of endianness problem required
} ascon_state;

typedef struct {
	uint64_t high;
	uint64_t low;
} ascon_nonce;

typedef struct {
	uint64_t high;
	uint64_t low;
	uint32_t trail;	//for ascon-80pq
} ascon_key;

typedef struct {
	uint64_t high;
	uint64_t low;
} ascon_tag;


int ascon_aead_state_init(ascon_state *state, ascon_rate_size bsize, ascon_r inter_r, ascon_key *key, ascon_nonce *nonce);
int ascon_aead_assoc_data_proc(ascon_state *state, ascon_rate_size bsize, ascon_r inter_r, size_t len, const char *payload);
int ascon_aead_payload_proc(ascon_state *state, ascon_rate_size bsize, ascon_r inter_r, size_t len, char *payload, ascon_aead_payload_proc_outmode outmode);
int ascon_aead_state_fin(ascon_state *state, ascon_rate_size bsize, ascon_key *key, ascon_tag *tag);

#endif
