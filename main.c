#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include "api.h"

#define TEST_LOOP 100000

int64_t cpucycles(void)
{
	unsigned int hi, lo;

    __asm__ __volatile__ ("rdtsc\n\t" : "=a" (lo), "=d"(hi));

    return ((int64_t)lo) | (((int64_t)hi) << 32);
}
void TEST_CCA_KEM1()
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char ss[_DGBLen];
	unsigned char dss[_DGBLen];

	printf("=========== CCA_KEM ENCAP DECAP TEST 1 ===========\n");

	crypto_kem_keypair(pk, sk);
	crypto_kem_enc(ct, ss, pk);
	crypto_kem_dec(dss, ct, sk);

	printf("pk  : ");
	for(int i=0; i<CRYPTO_PUBLICKEYBYTES; i++) printf("%02X", pk[i]);
	printf("\n");

	printf("sk  : ");
	for(int i=0; i<CRYPTO_SECRETKEYBYTES; i++) printf("%02X", sk[i]);
	printf("\n");

	printf("ct  : ");
	for(int i=0; i<CRYPTO_CIPHERTEXTBYTES; i++) printf("%02X", ct[i]);
	printf("\n");

	printf("ss  : ");
	for(int i=0; i<_DGBLen; i++) printf("%02X", ss[i]);
	printf("\n");

	printf("dss : ");
	for(int i=0; i<_DGBLen; i++) printf("%02X", dss[i]);
	printf("\n");

	printf("==================================================\n\n");

}

void TEST_CCA_KEM2()
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char ss[_DGBLen];
	unsigned char dss[_DGBLen];

	uint8_t  s[_MBLen];
	uint16_t   SK[_2H];
	uint16_t     A[_N];
	uint16_t     B[_N];

	printf("=========== CCA_KEM ENCAP DECAP TEST 2 ===========\n");

	crypto_kem_keypair(pk, sk);

	parseSK(s, SK, sk);
	parsePK(A, B, pk);

	_CCA_ENCAP(ct, ss, A, B);
	_CCA_DECAP(dss, ct, s, SK, A, B);

	printf("pk  : ");
	for(int i=0; i<CRYPTO_PUBLICKEYBYTES; i++) printf("%02X", pk[i]);
	printf("\n");

	printf("sk  : ");
	for(int i=0; i<CRYPTO_SECRETKEYBYTES; i++) printf("%02X", sk[i]);
	printf("\n");

	printf("ct  : ");
	for(int i=0; i<CRYPTO_CIPHERTEXTBYTES; i++) printf("%02X", ct[i]);
	printf("\n");

	printf("ss  : ");
	for(int i=0; i<_DGBLen; i++) printf("%02X", ss[i]);
	printf("\n");

	printf("dss : ");
	for(int i=0; i<_DGBLen; i++) printf("%02X", dss[i]);
	printf("\n");

	printf("==================================================\n\n");

}


void TEST_CCA_KEM3()
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char ss[_DGBLen];
	unsigned char dss[_DGBLen];

	int cnt = 0;

	printf("=========== CCA_KEM ENCAP DECAP TEST 3 ===========\n");

	//Generate public and secret key
	crypto_kem_keypair(pk, sk);

	//Encrypt and Decrypt message
	for(int j = 0; j < TEST_LOOP; j++)
	{
		crypto_kem_enc(ct, ss, pk);
		crypto_kem_dec(dss, ct, sk);

		if(memcmp(ss, dss, _DGBLen) != 0)
		{
			printf("ss[%d]  : ", j);
			for(int i=0; i<_DGBLen; i++) printf("%02X", ss[i]);
			printf("\n");
		
			printf("dss[%d] : ", j);
			for(int i=0; i<_DGBLen; i++) printf("%02X", dss[i]);
			printf("\n");
		
			cnt++;
		}
	}
	printf("count: %d\n", cnt);
	printf("==================================================\n\n");

}

void TEST_CCA_KEM_CLOCK1()
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char ss[_DGBLen];
	unsigned char dss[_DGBLen];

    unsigned long long cycles, cycles1, cycles2;
	printf("======== CCA KEM ENCAP DECAP SPEED TEST 1 ========\n");

	cycles=0;
	for (int i = 0; i < TEST_LOOP; i++)
	{
		cycles1 = cpucycles();
		crypto_kem_keypair(pk, sk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
	}
    printf("  KEYGEN runs in ................. %8lld cycles", cycles/TEST_LOOP);
    printf("\n"); 
	cycles=0;
	for (int i = 0; i < TEST_LOOP; i++)
	{
		cycles1 = cpucycles();
		crypto_kem_enc(ct, ss, pk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
	}

    printf("  ENCAP  runs in ................. %8lld cycles", cycles/TEST_LOOP);
    printf("\n"); 
	cycles=0;
	for (int i = 0; i < TEST_LOOP; i++)
	{
		cycles1 = cpucycles(); 
		crypto_kem_dec(dss, ct, sk);
		cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
	}

    printf("  DECAP  runs in ................. %8lld cycles", cycles/TEST_LOOP);
    printf("\n"); 

	printf("==================================================\n");
}

void TEST_CCA_KEM_CLOCK2()
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char ss[_DGBLen];
	unsigned char dss[_DGBLen];

	uint8_t  s[_MBLen];
	uint16_t   SK[_2H];
	uint16_t     A[_N];
	uint16_t     B[_N];

    unsigned long long cycles, cycles1, cycles2;
	printf("======== CCA KEM ENCAP DECAP SPEED TEST 2 ========\n");

	cycles=0;
	for (int i = 0; i < TEST_LOOP; i++)
	{
		cycles1 = cpucycles();
		crypto_kem_keypair(pk, sk);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
	}

	parseSK(s, SK, sk);
	parsePK(A, B, pk);

    printf("  KEYGEN runs in ................. %8lld cycles", cycles/TEST_LOOP);
    printf("\n"); 
	cycles=0;
	for (int i = 0; i < TEST_LOOP; i++)
	{
		cycles1 = cpucycles();
		_CCA_ENCAP(ct, ss, A, B);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
	}

    printf("  ENCAP  runs in ................. %8lld cycles", cycles/TEST_LOOP);
    printf("\n"); 
	cycles=0;
	for (int i = 0; i < TEST_LOOP; i++)
	{
		cycles1 = cpucycles(); 
		_CCA_DECAP(dss, ct, s, SK, A, B);
		cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
	}

    printf("  DECAP  runs in ................. %8lld cycles", cycles/TEST_LOOP);
    printf("\n"); 

	printf("==================================================\n");
}

int main(void)
{
#ifdef PARAM_1
	printf("PARAM_1\n");
#elif defined PARAM_2
	printf("PARAM_2\n");
#endif
	TEST_CCA_KEM1();
	TEST_CCA_KEM2();
	TEST_CCA_KEM3();
	TEST_CCA_KEM_CLOCK1();
	TEST_CCA_KEM_CLOCK2(); 

	return 0;
}
