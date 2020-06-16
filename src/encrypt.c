#include "api.h"

void HWT(uint16_t* out, uint8_t* in)
{
	AES_XOF_struct ctx;
	unsigned char diversifier[8] = {0,0,0,0,0,0,0,0};
	int maxlen = 0xfffffff;

	uint8_t seed[32];
	uint8_t index[_N];
	int cnt = 0;

	memset(index, 0,  _N);
	memset(out,   0, _4H);

	memcpy(seed, in, _MBLen);
	memset(seed + _MBLen, 0, 32 - _MBLen);

	seedexpander_init(&ctx, seed, diversifier, maxlen);

	while(cnt < _2H)
	{
		uint16_t tmp = 0;
		seedexpander(&ctx, (uint8_t*)&tmp, 2);

		if(tmp < _com)
		{
			tmp = tmp / _quotient;
			if (index[tmp] == 0)
			{
				out[cnt++] = tmp;
				index[tmp] = 1;
			}
		}	
	}

}

void parsePK(uint16_t* A, uint16_t* B, unsigned char* pk)
{
	AES_XOF_struct ctx;
	unsigned char diversifier[8] = {0,0,0,0,0,0,0,0};
	unsigned long maxlen = 0xfffffff;


	uint8_t tmp[792];

	//Generate A
	seedexpander_init(&ctx, pk, diversifier, maxlen);
//	seedexpander(&ctx, (uint8_t*)A, _2N);
//	for (int i = 0; i < _N; i++) A[i] &= _mod_q;



	seedexpander(&ctx, tmp, 792);
 
	for(int i = 0; i < 72; i++)
	{
		A[8*i + 0] = ((uint16_t)tmp[11*i + 0]       ) << 3  | (uint16_t)tmp[11*i + 1] >> 5;
		A[8*i + 1] = ((uint16_t)tmp[11*i + 1] & 0x1f) << 6  | (uint16_t)tmp[11*i + 2] >> 2;
		A[8*i + 2] = ((uint16_t)tmp[11*i + 2] & 0x03) << 9  | (uint16_t)tmp[11*i + 3] << 1 | tmp[11*i + 4] >> 7;
		A[8*i + 3] = ((uint16_t)tmp[11*i + 4] & 0x7f) << 4  | (uint16_t)tmp[11*i + 5] >> 4;
		A[8*i + 4] = ((uint16_t)tmp[11*i + 5] & 0x0f) << 7  | (uint16_t)tmp[11*i + 6] >> 1;
		A[8*i + 5] = ((uint16_t)tmp[11*i + 6] & 0x01) << 10 | (uint16_t)tmp[11*i + 7] << 2 | tmp[11*i + 8] >> 6;
		A[8*i + 6] = ((uint16_t)tmp[11*i + 8] & 0x3f) << 5  | (uint16_t)tmp[11*i + 9] >> 3;
		A[8*i + 7] = ((uint16_t)tmp[11*i + 9] & 0x07) << 8  | (uint16_t)tmp[11*i + 10];
	}







	//Parse B
	for(int i=0; i < _N; i++)
	{
		B[i] = pk[i+32];
	}
}

void parseSK(unsigned char* s, uint16_t* SK, unsigned char* sk)
{
	memcpy(s,sk,16);

	for(int i=0; i < 28; i++)
	{
		SK[4*i+0] = (((uint16_t)(sk[5*i+16] & 0xff)) << 2) | (((uint16_t)sk[5*i+17]) >> 6);
		SK[4*i+1] = (((uint16_t)(sk[5*i+17] & 0x3f)) << 4) | (((uint16_t)sk[5*i+18]) >> 4);
		SK[4*i+2] = (((uint16_t)(sk[5*i+18] &  0xf)) << 6) | (((uint16_t)sk[5*i+19]) >> 2);
		SK[4*i+3] = (((uint16_t)(sk[5*i+19] &  0x3)) << 8) | (((uint16_t)sk[5*i+20]) >> 0);
	}
}

void parseCT(uint16_t* C, unsigned char* ct)
{
		//Parse CT
	for(int i=0; i < _N; i++)
	{
		C[i] = ct[i];
	}

	for(int i=0; i < (_L >> 1); i++)
	{
		C[2*i + _N    ] = ct[i + _N] >> 4;
		C[2*i + _N + 1] = ct[i + _N] & 0xf;
	}
}

void pmul_gen(uint16_t c[_N], uint16_t a[_N], uint16_t idx[_2H])
{
	uint16_t tmp[_2N];

	memset(tmp, 0, _4N);

	for (int i = 0; i < _H; i++)
	{
		for (int j = 0; j < _N; j++)
		{
			tmp[j + idx[i]]    += a[j];
			tmp[j + idx[i+_H]] -= a[j];
		}
	}

	//reduction
	for (int i = 0; i < _hN; i++) 
	{
		int j = i + _hN;
		
		c[i] = tmp[i] - tmp[i + _3hN] - tmp[i + _N];
		c[j] = tmp[j]                 + tmp[i + _N];

		c[i] = ((c[i] + (1 << (_log_q - _log_p - 1))) >> (_log_q - _log_p));
		c[j] = ((c[j] + (1 << (_log_q - _log_p - 1))) >> (_log_q - _log_p));

		c[i] = c[i]	& _mod_p;
		c[j] = c[j]	& _mod_p;
	}
}

void pmul_enc(uint16_t *C, int16_t *A, uint16_t *B, uint16_t *idx)
{
	uint16_t tmp1[_2N];
	uint16_t tmp2[_2N];

	memset(tmp1, 0, _4N);
	memset(tmp2, 0, _4N);

	for (int i = 0; i < _H; i++)
	{
		int t1 = idx[i], t2 = idx[i+_H];
		for (int j = 0; j < _N; j++)
		{
			tmp1[j + t1] += A[j];
			tmp1[j + t2] -= A[j];
			tmp2[j + t1] += B[j];
			tmp2[j + t2] -= B[j];
		}
	}

	for (int i = 0; i < _hN; i++) 
	{
		int j = i + _hN;
		
		C[i] = tmp1[i] - tmp1[i + _3hN] - tmp1[i + _N];
		C[j] = tmp1[j]                  + tmp1[i + _N];

		C[i] = ((C[i] + (1 << (_log_q - _log_p - 1))) >> (_log_q - _log_p));
		C[j] = ((C[j] + (1 << (_log_q - _log_p - 1))) >> (_log_q - _log_p));

		C[i] = C[i] & _mod_p; 
		C[j] = C[j] & _mod_p; 
	}

	for (int i = _N; i < _CTLen; i++) 
	{
		int j = i - _hN - _L;

		C[i] = tmp2[j] - tmp2[j + _N] - tmp2[j + _3hN];

		C[i] = ((C[i] + (1 << (_log_p - _log_t - 1))) >> (_log_p - _log_t));

		C[i] = C[i] & _mod_t; 
	}

}

void pmul_dec(uint16_t* C, uint16_t* A, uint16_t* B)
{
	uint16_t tmp[_2N];

	memset(tmp, 0, _4N);

	for (int i = 0; i < _H; i++)
	{
		for (int j = 0; j < _N; j++)
		{
			tmp[j + B[i]]    += A[j];
			tmp[j + B[i+_H]] -= A[j];
		}
	}

	for (int i = 0; i < _L; i++) 
	{
		int j = i + _hN - _L;

		C[i] = (tmp[j] - tmp[j + _N] - tmp[j + _3hN]) & _mod_q;
	}
}


void _CPA_Enc(uint16_t* C, uint16_t* r, uint8_t* m, uint16_t *A, uint16_t *B)
{
	pmul_enc(C, A, B, r);

	for (int i = 0; i < _L; i++)
	{
		uint8_t tmp = (((m[i >> 3] >> (7 - (i % 8))) & 1) << (_log_t-1))^_block_t;
		C[_N + i] = (C[_N + i] + tmp) & _mod_t;
	}
}

void _CPA_Dec(uint8_t *m, uint16_t *C, uint16_t* SK)
{
	uint16_t tmp[_L];

	memset(m, 0, _MBLen);
	pmul_dec(tmp, C, SK);

	for (int i = 0; i < _L; i++)
	{
		uint16_t tmp16 = ((C[i + _N] << (_log_p - _log_t)) - tmp[i]) & _mod_p;
		m[i >> 3] ^= (tmp16 >> (_log_p - 1)) << (7 - i % 8);
	}
}

int _CCA_ENCAP(unsigned char *ct, unsigned char *ss, uint16_t *A, uint16_t *B)
{
	AES_XOF_struct ctx1;
	SHA256_CTX ctx2;

	uint16_t C[_N + _L];

	uint8_t  delta[16];
	uint16_t     r[_2H];
	uint8_t digest[32] = { 0, };

	memset(delta, 0, 16);
	memset(r,     0, _4H);

	randombytes(delta, _MBLen);
	SHA256(delta, _MBLen, digest);
	HWT(r, digest);

	// STEP 3: Compute CPA
	_CPA_Enc(C, r, delta, A, B);

	//Encode CT
	for(int i=0; i < 576; i++)
	{
		ct[i] = C[i];
	}

	for(int i=0; i < 64; i++)
	{
		ct[i+576] = (C[2*i+576] << 4) | C[2*i+577];
	}

	SHA256_Init(&ctx2);
	SHA256_Update(&ctx2, ct, CRYPTO_CIPHERTEXTBYTES);
	SHA256_Update(&ctx2, delta, _MBLen);
	SHA256_Final(ss, &ctx2);

	return 0;
}

int _CCA_DECAP(unsigned char *ss, unsigned char *ct, uint8_t *s, uint16_t *SK, uint16_t *A, uint16_t *B)
{
	SHA256_CTX ctx;

	uint16_t C[_N + _L];
	unsigned char delta[16];
	uint8_t digest[32] = { 0, };
	uint16_t     r[_2H];
	int16_t tC[_CTLen];
	uint8_t    tmp[_CTBLen + _DGBLen];

	//Parse CT
	parseCT(C, ct);

	_CPA_Dec(delta, C, SK);

	SHA256(delta, _MBLen, digest);
	HWT(r, digest);

	_CPA_Enc(tC, r, delta, A, B);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ct, CRYPTO_CIPHERTEXTBYTES);

	if(memcmp(C, tC, _N + _L) == 0)
	{
		SHA256_Update(&ctx, delta, _MBLen);
	}else
	{
		SHA256_Update(&ctx, s, _MBLen);
	}

	SHA256_Final(ss, &ctx);

	return 0;
}

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
	AES_XOF_struct ctx;
	unsigned char diversifier[8] = {0,0,0,0,0,0,0,0};
	int maxlen = 0xfffffff;

	uint16_t A[_N];
	uint16_t B[_N];
	uint16_t SK[_2H];
	uint8_t s[16];

	uint8_t tmp[_N << 1];
	uint8_t w[16];


	memset(A,0,_N);
	memset(B,0,_N);
	memset(SK,0,_2H);

	//s || x
	randombytes(sk,16);
	randombytes(w, 16);
	HWT(SK, w);


	for(int i=0; i < _hH; i++)
	{
		sk[5*i+16] = SK[4*i+0] >> 2;
		sk[5*i+17] = SK[4*i+0] << 6 | SK[4*i+1] >> 4;
		sk[5*i+18] = SK[4*i+1] << 4 | SK[4*i+2] >> 6;
		sk[5*i+19] = SK[4*i+2] << 2 | SK[4*i+3] >> 8;
		sk[5*i+20] = SK[4*i+3];
	}

	randombytes(pk,32);
	seedexpander_init(&ctx, pk, diversifier, maxlen);
//	seedexpander(&ctx, (uint8_t*)A, _2N);
//	for (int i = 0; i < _N; i++) A[i] &= _mod_q;



	seedexpander(&ctx, tmp, 792);
 
	for(int i = 0; i < 72; i++)
	{
		A[8*i + 0] = ((uint16_t)tmp[11*i + 0]       ) << 3  | (uint16_t)tmp[11*i + 1] >> 5;
		A[8*i + 1] = ((uint16_t)tmp[11*i + 1] & 0x1f) << 6  | (uint16_t)tmp[11*i + 2] >> 2;
		A[8*i + 2] = ((uint16_t)tmp[11*i + 2] & 0x03) << 9  | (uint16_t)tmp[11*i + 3] << 1 | tmp[11*i + 4] >> 7;
		A[8*i + 3] = ((uint16_t)tmp[11*i + 4] & 0x7f) << 4  | (uint16_t)tmp[11*i + 5] >> 4;
		A[8*i + 4] = ((uint16_t)tmp[11*i + 5] & 0x0f) << 7  | (uint16_t)tmp[11*i + 6] >> 1;
		A[8*i + 5] = ((uint16_t)tmp[11*i + 6] & 0x01) << 10 | (uint16_t)tmp[11*i + 7] << 2 | tmp[11*i + 8] >> 6;
		A[8*i + 6] = ((uint16_t)tmp[11*i + 8] & 0x3f) << 5  | (uint16_t)tmp[11*i + 9] >> 3;
		A[8*i + 7] = ((uint16_t)tmp[11*i + 9] & 0x07) << 8  | (uint16_t)tmp[11*i + 10];
	}


	pmul_gen(B, A, SK);


	//Encode B
	for(int i=0; i < _N; i++)
	{
		pk[i+32] = B[i];
	}

	memcpy(sk + CRYPTO_SECRETKEYBYTES, pk, CRYPTO_PUBLICKEYBYTES);
}

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, unsigned char *pk)
{
	uint16_t A[_N];
	uint16_t B[_N];

	parsePK(A, B, pk);
	_CCA_ENCAP(ct, ss, A, B);

	return 0;
}


int crypto_kem_dec(unsigned char *ss, unsigned char *ct, unsigned char *sk)
{
	uint8_t    s[16];
	uint16_t SK[_2H];
	uint16_t   A[_N];
	uint16_t   B[_N];


	//Parse SK
	parseSK(s, SK, sk);
	parsePK(A, B, sk + CRYPTO_SECRETKEYBYTES);

	_CCA_DECAP(ss, ct, s, SK, A, B);

	return 0;
}