#ifndef _API_H_
#define _API_H_

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/sha.h>

#include "rng.h"
#include "params.h"

void parsePK(uint16_t* A, uint16_t* B, unsigned char* pk);
void parseSK(unsigned char* s, uint16_t* SK, unsigned char* sk);
int _CCA_ENCAP(unsigned char *ct, unsigned char *ss, uint16_t *A, uint16_t *B);
int _CCA_DECAP(unsigned char *ss, unsigned char *ct, uint8_t *s, uint16_t *SK, uint16_t *A, uint16_t *B);

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk); 
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, unsigned char *ct, unsigned char *sk);  

#endif
