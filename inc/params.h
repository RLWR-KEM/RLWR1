#ifndef _PARAMS_H_
#define _PARAMS_H_

#define PARAM_1

#ifdef PARAM_1
	#define _hN  288
	#define _N 576
	#define _3hN 864
	#define _2N  1152
	#define _4N  2304

	#define _hH 28
	#define _H  56
	#define _2H 112
	#define _4H 224

	#define _log_q 11
	#define _log_p 8
	#define _log_t 4
	#define _mod_q 0x7ff
	#define _mod_p 0xff
	#define _mod_t 0xf

	#define _CTLen 704
	#define _CTBLen 1408
	#define _MBLen 16
	#define _DGBLen	32

	#define _block_t 0x4
	#define _L 128

	#define _quotient 113
	#define _com 65088

	#define CRYPTO_SECRETKEYBYTES 156
	#define CRYPTO_PUBLICKEYBYTES 608
	#define CRYPTO_CIPHERTEXTBYTES 640

#endif
#endif
