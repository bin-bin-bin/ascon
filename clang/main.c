#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef __MINGW32__
#include <sys/mman.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include "ascon.h"

void print_hex(const char *s, size_t len) {
  do {
	  printf("%02X", (uint8_t)*s++);
  } while (--len);
}

double measure_mbps(size_t data_len, clock_t start, clock_t end) {
    double duration = ((double)(end - start)) / CLOCKS_PER_SEC; // Time in seconds
    double megabits = (data_len * 8) / 1e6; // Data length in megabits (8 bits per byte)
    return megabits / duration; // Mbps = Megabits per second
}

int main(int argc, char *argv[]) {
	if (argc == 1) {
		const char
		*key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
		*nonce = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
		*assoc_data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
		char
		*plain_text = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
		*cipher_text = NULL, *tag = (char *)malloc(16 * sizeof(char));
		for (size_t len = 0, count = 1; len <= 32; len++) for (size_t assoc_len = 0; assoc_len <= 32; assoc_len++, count++) {
			printf("\nCount = %lld", count);
			printf("\nKey = ");
			print_hex(key, 16);
			printf("\nNonce = ");
			print_hex(nonce, 16);
			printf("\nPT = ");
			if (len) print_hex(plain_text, len);
			printf("\nAD = ");
			if (assoc_len) print_hex(assoc_data, assoc_len);

			cipher_text = len ? (char *)memcpy(malloc(len * sizeof(char)), plain_text, len * sizeof(char)) : NULL;
			int ret = ascon_128a_encrypt(key, nonce, assoc_len, assoc_data, len, cipher_text, tag);

			if (!ret) {
				printf("\nCT = ");
				if (len) print_hex(cipher_text, len);
				print_hex(tag, 16);
				printf("\n");

				char *decipher_text = len ? (char *)memcpy(malloc(len * sizeof(char)), cipher_text, len * sizeof(char)) : NULL;
				ret = ascon_128a_decrypt(key, nonce, tag, assoc_len, assoc_data, len, decipher_text);
				if (ret) printf("Decrypt error! %d", ret);
				else if (len) for (size_t i = 0; i < len; i++) {
					if (decipher_text[i] != plain_text[i]) {
						printf("Plaintext mismatch!\n");
						print_hex(plain_text, len);
						printf("\n");
						print_hex(decipher_text, len);
						ret = -8;
						break;
					}
				}
				if (decipher_text) free(decipher_text);
			} else printf("Encrypt error! %d", ret);

			if (cipher_text) free(cipher_text);
			if (ret) return -1;
		}
		free(tag);
	}
#ifndef __MINGW32__
	else if (argc < 8) {
        fprintf(stderr, "Usage: %s [--enc | [--dec --tag <16-byte_tag>]] --key <16-byte_key> --nonce <16-byte_nonce> [--assoc <associated data string>] --file <file_path>\n", argv[0]);
        return -1;
    }
	else {
	    char *file = NULL;
	    char *key = NULL;
	    char *nonce = NULL;
	    char *assoc = NULL;
	    char *tag = NULL;
	    int mode = 0; // 1 for encryption, 2 for decryption

	    // Parse command-line arguments
	    for (int i = 1; i < argc; i += 2) {
	        if (strcmp(argv[i], "--file") == 0) {
	            file = argv[i + 1];
	        } else if (strcmp(argv[i], "--enc") == 0) {
	            mode = 1;
	            i--; // No value for this flag, adjust loop increment
	        } else if (strcmp(argv[i], "--dec") == 0) {
	            mode = 2;
	            i--; // No value for this flag, adjust loop increment
	        } else if (strcmp(argv[i], "--key") == 0) {
	            key = argv[i + 1];
	        } else if (strcmp(argv[i], "--nonce") == 0) {
	            nonce = argv[i + 1];
	        } else if (strcmp(argv[i], "--assoc") == 0) {
	            assoc = argv[i + 1];
	        } else if (strcmp(argv[i], "--tag") == 0) {
	            tag = argv[i + 1];
	        } else {
	            fprintf(stderr, "Invalid argument: %s\n", argv[i]);
	            return -1;
	        }
	    }

	    // Validate required arguments
	    if (file == NULL || key == NULL || nonce == NULL || mode == 0) {
	        fprintf(stderr, "All of --file, --key, --nonce, and either --enc or --dec must be specified.\n");
	        return -1;
	    }

	    // Validate key and nonce length
	    if (strlen(key) != 16 || strlen(nonce) != 16) {
	        fprintf(stderr, "Error: Both --key and --nonce must be 16 bytes long.\n");
	        return -1;
	    }

	    // Validate tag input
	    if (mode == 2 && (tag == NULL || strlen(tag) != 16)) {
	        fprintf(stderr, "Error: For decryption, --tag must be specified and must be 16 bytes long.\n");
	        return -1;
	    }

	    // Open the file
	    int fd = open(file, O_RDWR, 0666);
	    if (fd == -1) {
	        perror("open file");
	        return -3;
	    }

	    // Get the file size
	    struct stat s;
	    if (fstat(fd, &s) == -1) {
	        perror("fstat file");
	        close(fd);
	        return -2;
	    }

	    // Map the file into memory
	    char *payload = mmap(NULL, s.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	    if (payload == MAP_FAILED) {
	        perror("mmap file");
	        close(fd);
	        return -3;
	    }

	    clock_t start;
	    double mbps;
	    // Encrypt or decrypt based on the mode
	    if (mode == 1) {
	        printf("Encrypting file...\n");
	        tag = (char *)malloc(16 * sizeof(char));
	        start = clock();
	        if (ascon_128a_encrypt(key, nonce, assoc ? strlen(assoc) : 0, assoc, s.st_size, payload, tag)) {
	        	free(tag);
		        munmap(payload, s.st_size);
		        close(fd);
	        	perror("encryption");
	        	return -4;
	        } else {
	        	mbps = measure_mbps(s.st_size, start, clock());
	        	printf("Encryption successfully completed. \n");
	        	printf("Speed: %.2f Mbps\n", mbps);
	        	printf("Tag: ");
	        	print_hex(tag, 16);
	        	printf("\n");
	        	free(tag);
	        }
	    } else if (mode == 2) {
	        printf("Decrypting file...\n");
	        start = clock();
	        if (ascon_128a_decrypt(key, nonce, tag, assoc ? strlen(assoc) : 0, assoc, s.st_size, payload)) {
				munmap(payload, s.st_size);
				close(fd);
				perror("decryption");
				return -4;
			} else {
	        	mbps = measure_mbps(s.st_size, start, clock());
	        	printf("Decryption successfully completed. \n");
	        	printf("Speed: %.2f Mbps\n", mbps);
	        }
	    }

	    // Unmap the file
	    if (munmap(payload, s.st_size) == -1) {
	        perror("munmap file");
	    }

	    // Close the file
	    close(fd);

	    return 0;
	}
#endif
}
