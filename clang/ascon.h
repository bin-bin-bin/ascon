#ifndef ASCON_H_
#define ASCON_H_

#include <stdint.h>
#include <string.h>
#include "ascon_core.h"

int ascon_128a_encrypt(const char key[16], const char nonce[16],
						 size_t assoc_len, const char *assoc_data,
						 size_t len,       char *payload,
						 char *tag);

int ascon_128a_decrypt(const char key[16], const char nonce[16], const char tag[16],
						 size_t assoc_len, const char *assoc_data,
						 size_t len,       char *payload);

#endif
