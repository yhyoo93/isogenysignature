/********************************************************************************************
* A Post-Quantum Digital Signature Scheme Based on Supersingular Isogenies
*
*
*    Copyright (c) Youngho Yoo.
*
*
* Abstract: Testing the isogeny-based signature scheme.
*
*********************************************************************************************/ 

#include "../SIDH.h"
#include "test_extras.h"
#include <malloc.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include "../keccak.c"
#include "../sha256.c"
#include <pthread.h>



// Benchmark and test parameters  
#define BENCH_LOOPS       10      // Number of iterations per bench 
#define TEST_LOOPS        10      // Number of iterations per test
#define NUM_ROUNDS		 248

int NUM_THREADS = 1;
int CUR_ROUND = 0;
pthread_mutex_t RLOCK;

// Used in BigMont tests
static const uint64_t output1[12] = { 0x30E9AFA5BF75A92F, 0x88BC71EE9E221028, 0x999A50A9EE3B9A8E, 0x77E2934BD8D38B5A, 0x2668CAFC2933DB58, 0x457C65F7AD941041, 
                                      0x72EA3D5F92F33153, 0x6E04B56AF98D6285, 0x28FA680C091A9AE2, 0xE73DFE058AFD79ED, 0x902CD9E695BC7260, 0x00006FAC6F6E88AF };
static const uint64_t scalar1[12] = { 0x154A166BBD471DF4, 0xBF7CA3B41010FE6B, 0xC34BD28655936246, 0xAD8E8F394D3428B5, 0x275B1116E6B3BF08, 0x3C024A3CC03A6AFC,
                                      0x2300A0049FC615AF, 0xA0060FEC19263F0B, 0x69A1EB9091B8162C, 0xFDBE1DF28CDC03EE, 0xAA2030E6922EF3D5, 0x0000075E7401FA0E };


CRYPTO_STATUS cryptotest_kex(PCurveIsogenyStaticData CurveIsogenyData)
{ // Testing key exchange
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;   // Number of bytes in a field element 
    unsigned int obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    unsigned char *PrivateKeyA, *PrivateKeyB, *PublicKeyA, *PublicKeyB, *SharedSecretA, *SharedSecretB;
    PCurveIsogenyStruct CurveIsogeny = {0};
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool valid_PublicKey = false;
    bool passed = true;
        
    // Allocating memory for private keys, public keys and shared secrets
    PrivateKeyA = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
    PrivateKeyB = (unsigned char*)calloc(1, obytes);
    PublicKeyA = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)
    PublicKeyB = (unsigned char*)calloc(1, 4*2*pbytes);
    SharedSecretA = (unsigned char*)calloc(1, 2*pbytes);    // One element in GF(p^2)  
    SharedSecretB = (unsigned char*)calloc(1, 2*pbytes);

    printf("\n\nTESTING ISOGENY-BASED KEY EXCHANGE \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve isogeny system: %s \n\n", CurveIsogenyData->CurveIsogeny);

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = KeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny, true);                     // Get some value as Alice's secret key and compute Alice's public key
    if (Status != CRYPTO_SUCCESS) {                                                  
        goto cleanup;
    }  
    Status = Validate_PKA(PublicKeyA, &valid_PublicKey, CurveIsogeny);                   // Bob validating Alice's public key
    if (Status != CRYPTO_SUCCESS) {  
        goto cleanup;
    }  
    if (valid_PublicKey != true) {
        passed = false;
        Status = CRYPTO_ERROR_PUBLIC_KEY_VALIDATION;
        goto finish;
    }

    Status = KeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);                     // Get some value as Bob's secret key and compute Bob's public key
    if (Status != CRYPTO_SUCCESS) {                                                  
        goto cleanup;
    }
    Status = Validate_PKB(PublicKeyB, &valid_PublicKey, CurveIsogeny);                   // Alice validating Bob's public key
    if (Status != CRYPTO_SUCCESS) {   
        goto cleanup;
    }  
    if (valid_PublicKey != true) {
        passed = false;
        Status = CRYPTO_ERROR_PUBLIC_KEY_VALIDATION;
        goto finish;
    }
    
    Status = SecretAgreement_A(PrivateKeyA, PublicKeyB, SharedSecretA, CurveIsogeny, NULL);    // Alice computes her shared secret using Bob's public key
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }    
    Status = SecretAgreement_B(PrivateKeyB, PublicKeyA, SharedSecretB, CurveIsogeny, NULL, NULL);    // Bob computes his shared secret using Alice's public key
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (compare_words((digit_t*)SharedSecretA, (digit_t*)SharedSecretB, NBYTES_TO_NWORDS(2*pbytes)) != 0) {
        passed = false;
        Status = CRYPTO_ERROR_SHARED_KEY;
    }

finish:
    if (passed == true) printf("  Key exchange tests ........................................... PASSED");
    else { printf("  Key exchange tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n"); 

cleanup:
    SIDH_curve_free(CurveIsogeny);
    clear_words((void*)PrivateKeyA, NBYTES_TO_NWORDS(obytes));
    clear_words((void*)PrivateKeyB, NBYTES_TO_NWORDS(obytes));
    clear_words((void*)PublicKeyA, NBYTES_TO_NWORDS(4*2*pbytes));
    clear_words((void*)PublicKeyB, NBYTES_TO_NWORDS(4*2*pbytes));
    clear_words((void*)SharedSecretA, NBYTES_TO_NWORDS(2*pbytes));
    clear_words((void*)SharedSecretB, NBYTES_TO_NWORDS(2*pbytes));

    return Status;
}


CRYPTO_STATUS cryptotest_BigMont(PCurveIsogenyStaticData CurveIsogenyData)
{ // Testing BigMont
    unsigned int i, j; 
    digit_t scalar[BIGMONT_NWORDS_ORDER] = {0};
    felm_t x = {0};
    PCurveIsogenyStruct CurveIsogeny = {0};
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed = true;

    printf("\n\nTESTING ELLIPTIC CURVE BIGMONT \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    copy_words((digit_t*)scalar1, scalar, BIGMONT_NWORDS_ORDER);    // Set scalar
    x[0] = 3;                                                       // Set initial x-coordinate

    for (i = 0; i < TEST_LOOPS; i++)
    {
        for (j = 0; j < BIGMONT_NWORDS_ORDER-1; j++) {
            scalar[j] = (scalar[j] >> 1) | (scalar[j+1] << (RADIX-1));  
        }
        scalar[BIGMONT_NWORDS_ORDER-1] >>= 1;

        Status = BigMont_ladder((unsigned char*)x, scalar, (unsigned char*)x, CurveIsogeny);   
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }
    }

    if (compare_words((digit_t*)x, (digit_t*)output1, BIGMONT_NWORDS_ORDER) != 0) {
        passed = false;
        Status = CRYPTO_ERROR_SHARED_KEY;
    }

    if (passed == true) printf("  BigMont's scalar multiplication tests ........................ PASSED");
    else { printf("  BigMont's scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n"); 

cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}


CRYPTO_STATUS cryptorun_kex(PCurveIsogenyStaticData CurveIsogenyData)
{ // Benchmarking key exchange
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    unsigned char *PrivateKeyA, *PrivateKeyB, *PublicKeyA, *PublicKeyB, *SharedSecretA, *SharedSecretB;
    bool valid_PublicKey = false;
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;
        
    // Allocating memory for private keys, public keys and shared secrets
    PrivateKeyA = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
    PrivateKeyB = (unsigned char*)calloc(1, obytes);
    PublicKeyA = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)
    PublicKeyB = (unsigned char*)calloc(1, 4*2*pbytes);
    SharedSecretA = (unsigned char*)calloc(1, 2*pbytes);    // One element in GF(p^2)  
    SharedSecretB = (unsigned char*)calloc(1, 2*pbytes);

    printf("\n\nBENCHMARKING ISOGENY-BASED KEY EXCHANGE \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve isogeny system: %s \n\n", CurveIsogenyData->CurveIsogeny);

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Benchmarking Alice's key generation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = KeyGeneration_A(PrivateKeyA, PublicKeyA, CurveIsogeny, true);                     
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) printf("  Alice's key generation runs in ............................... %10lld cycles", cycles/BENCH_LOOPS);
    else { printf("  Alice's key generation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Bob's key generation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = KeyGeneration_B(PrivateKeyB, PublicKeyB, CurveIsogeny);                     
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) printf("  Bob's key generation runs in ................................. %10lld cycles", cycles/BENCH_LOOPS);
    else { printf("  Bob's key generation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Alice's public key validation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = Validate_PKA(PublicKeyA, &valid_PublicKey, CurveIsogeny);                     
        if (Status != CRYPTO_SUCCESS || valid_PublicKey != true) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) printf("  Alice's public key validation runs in ........................ %10lld cycles", cycles/BENCH_LOOPS);
    else { printf("  Alice's public key validation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Bob's public key validation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = Validate_PKB(PublicKeyB, &valid_PublicKey, CurveIsogeny);                     
        if (Status != CRYPTO_SUCCESS || valid_PublicKey != true) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) printf("  Bob's public key validation runs in .......................... %10lld cycles", cycles/BENCH_LOOPS);
    else { printf("  Bob's public key validation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Alice's shared key computation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = SecretAgreement_A(PrivateKeyA, PublicKeyB, SharedSecretA, CurveIsogeny, NULL);                     
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) printf("  Alice's shared key computation runs in ....................... %10lld cycles", cycles/BENCH_LOOPS);
    else { printf("  Alice's shared key computation failed"); goto cleanup; } 
    printf("\n");

    // Benchmarking Bob's shared key computation
    passed = true;
    cycles = 0;
    for (n = 0; n < BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = SecretAgreement_B(PrivateKeyB, PublicKeyA, SharedSecretB, CurveIsogeny, NULL, NULL);                     
        if (Status != CRYPTO_SUCCESS) {                                                  
            passed = false;
            break;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) printf("  Bob's shared key computation runs in ......................... %10lld cycles", cycles/BENCH_LOOPS);
    else { printf("  Bob's shared key computation failed"); goto cleanup; } 
    printf("\n");

cleanup:
    
    SIDH_curve_free(CurveIsogeny);
    clear_words((void*)PrivateKeyA, NBYTES_TO_NWORDS(obytes));
    clear_words((void*)PrivateKeyB, NBYTES_TO_NWORDS(obytes));
    clear_words((void*)PublicKeyA, NBYTES_TO_NWORDS(4*2*pbytes));
    clear_words((void*)PublicKeyB, NBYTES_TO_NWORDS(4*2*pbytes));
    clear_words((void*)SharedSecretA, NBYTES_TO_NWORDS(2*pbytes));
    clear_words((void*)SharedSecretB, NBYTES_TO_NWORDS(2*pbytes));

    return Status;
}


CRYPTO_STATUS cryptorun_BigMont(PCurveIsogenyStaticData CurveIsogenyData)
{ // Benchmarking BigMont
    unsigned int i; 
    digit_t scalar[BIGMONT_NWORDS_ORDER] = {0};
    f2elm_t x = {0};
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    printf("\n\nBENCHMARKING ELLIPTIC CURVE BIGMONT \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    x[0][0] = 3;                                                    // Set initial x-coordinate
    
    passed = true;
    cycles = 0;
    for (i = 0; i < BENCH_LOOPS; i++)
    {        
        // Choose a random number in [1, BigMont_order-1] as scalar
        Status = random_BigMont_mod_order(scalar, CurveIsogeny);    
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }

        cycles1 = cpucycles();
        Status = BigMont_ladder((unsigned char*)x, scalar, (unsigned char*)x, CurveIsogeny);   
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }   
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (passed) printf("  BigMont's scalar multiplication runs in ...................... %10lld cycles", cycles/BENCH_LOOPS);
    else { printf("  BigMont's scalar multiplication failed"); goto cleanup; } 
    printf("\n");

cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}





char *join_strings(const char *s1, ...)
{
  va_list args;
  const char *s;
  char *p, *result;
  unsigned long l, m, n;
 
  m = n = strlen(s1);
  va_start(args, s1);
  while ((s = va_arg(args, char *))) {
    l = strlen(s);
    if ((m += l) < l) break;
  }
  va_end(args);
  if (s || m >= INT_MAX) return NULL;
 
  result = (char *)malloc(m + 1);
  if (!result) return NULL;
 
  memcpy(p = result, s1, n);
  p += n;
  va_start(args, s1);
  while ((s = va_arg(args, char *))) {
    l = strlen(s);
    if ((n += l) < l || n > m) break;
    memcpy(p, s, l);
    p += l;
  }
  va_end(args);
  if (s || m != n || p != result + n) {
    free(result);
    return NULL;
  }
 
  *p = 0;
  return result;
}


char* join_strings_array(char* strings[], char* seperator, int count) {
    char* str = NULL;             /* Pointer to the joined strings  */
    size_t total_length = 0;      /* Total length of joined strings */
    int i = 0;                    /* Loop counter                   */

    /* Find total length of joined strings */
    for (i = 0; i < count; i++) total_length += strlen(strings[i]);
    total_length++;     /* For joined string terminator */
    total_length += strlen(seperator) * (count - 1); // for seperators

    str = (char*) malloc(total_length);  /* Allocate memory for joined strings */
    str[0] = '\0';                      /* Empty string we can append to      */

    /* Append all the strings */
    for (i = 0; i < count; i++) {
        strcat(str, strings[i]);
        if (i < (count - 1)) strcat(str, seperator);
    }

    return str;
}

void hashdata(unsigned int pbytes, unsigned char** comm1, unsigned char** comm2, uint8_t* HashResp, int hlen, int dlen, uint8_t *data, uint8_t *cHash, int cHashLength) {
    int r;
    for (r=0; r<NUM_ROUNDS; r++) {
        memcpy(data + (r * 2*pbytes), comm1[r], 2*pbytes);
        memcpy(data + (NUM_ROUNDS * 2*pbytes) + (r * 2*pbytes), comm2[r], 2*pbytes);
    }
    memcpy(data + (2 * NUM_ROUNDS * 2*pbytes), HashResp, 2 * NUM_ROUNDS * hlen);

    keccak(data, dlen, cHash, cHashLength);
}


union Response {
    unsigned char *randm;
    point_proj_t psiS;
};

struct Signature {
    unsigned char *Commitments1[NUM_ROUNDS];
    unsigned char *Commitments2[NUM_ROUNDS];
    unsigned char *HashResp;
    unsigned char *Randoms[NUM_ROUNDS];
    point_proj *psiS[NUM_ROUNDS];
};



CRYPTO_STATUS isogeny_keygen(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PrivateKey, unsigned char *PublicKey) {
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    bool valid_PublicKey = false;
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;


    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Generate Peggy(Bob)'s keys
    passed = true;
    cycles1 = cpucycles();
    Status = KeyGeneration_B(PrivateKey, PublicKey, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {                                                  
        passed = false;
    }
    cycles2 = cpucycles();
    cycles = cycles2 - cycles1;
    if (passed) {
        //printf("  Key generated in ................... %10lld cycles", cycles);
    } else { 
        printf("  Key generation failed"); goto cleanup; 
    } 
    printf("\n");


    
cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}


typedef struct thread_params_sign {
	PCurveIsogenyStruct *CurveIsogeny;
	unsigned char *PrivateKey;
	unsigned char *PublicKey;
	struct Signature *sig;
	
	unsigned int pbytes;
	unsigned int n;
	unsigned int obytes;
} thread_params_sign;


void *sign_thread(void *TPS) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	thread_params_sign *tps = (thread_params_sign*) TPS;

	int r=0;

	while (1) {
		int stop=0;

		pthread_mutex_lock(&RLOCK);
		if (CUR_ROUND >= NUM_ROUNDS) {
			stop=1;
		} else {
			r = CUR_ROUND;
			CUR_ROUND++;
		}
		pthread_mutex_unlock(&RLOCK);

		if (stop) break;

		//printf("round: %d\n", CUR_ROUND);


		//cycles1 = cpucycles();

        tps->sig->Randoms[r] = (unsigned char*)calloc(1, tps->obytes);
        tps->sig->Commitments1[r] = (unsigned char*)calloc(1, 2*tps->pbytes);
        tps->sig->Commitments2[r] = (unsigned char*)calloc(1, 2*tps->pbytes);
        tps->sig->psiS[r] = calloc(1, sizeof(point_proj));

        // Pick random point R and compute E/<R>
        f2elm_t A;

        unsigned char *TempPubKey;
        TempPubKey = (unsigned char*)calloc(1, 4*2*tps->pbytes);

        Status = KeyGeneration_A(tps->sig->Randoms[r], TempPubKey, *(tps->CurveIsogeny), true);
        if(Status != CRYPTO_SUCCESS) {
            printf("Random point generation failed");
        }
        
        to_fp2mont(((f2elm_t*)TempPubKey)[0], A);
        fp2copy751(A, *(f2elm_t*)tps->sig->Commitments1[r]);

        ////////////////////////////
        //TODO: compute using A instead
        Status = SecretAgreement_B(tps->PrivateKey, TempPubKey, tps->sig->Commitments2[r], *(tps->CurveIsogeny), NULL, tps->sig->psiS[r]);
        if(Status != CRYPTO_SUCCESS) {
            printf("Random point generation failed"); 
        }

        //cycles2 = cpucycles();
        //cycles = cycles2 - cycles1;
        //printf("ZKP round %d ran in ............ %10lld cycles\n", r, cycles);
        //totcycles += cycles;
	}


}


CRYPTO_STATUS isogeny_sign(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PrivateKey, unsigned char *PublicKey, struct Signature *sig) {
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2, totcycles=0;

    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        //goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        //goto cleanup;
    }

    // Run the ZKP rounds
    int r;
    pthread_t sign_threads[NUM_THREADS];
    CUR_ROUND = 0;
    if (pthread_mutex_init(&RLOCK, NULL)) {
    	printf("ERROR: mutex init failed\n");
    	return 1;
    }
    thread_params_sign tps = {&CurveIsogeny, PrivateKey, PublicKey, sig, pbytes, n, obytes};

    int t;
    for (t=0; t<NUM_THREADS; t++) {
    	if (pthread_create(&sign_threads[t], NULL, sign_thread, &tps)) {
    		printf("ERROR: Failed to create thread %d\n", t);
    	}
    }

    for (t=0; t<NUM_THREADS; t++) {
    	pthread_join(sign_threads[t], NULL);
  	}

    //printf("Average time for ZKP round ...... %10lld cycles\n", totcycles/NUM_ROUNDS);


    // Commit to responses (hash)
    int HashLength = 32; //bytes
    sig->HashResp = calloc(2*NUM_ROUNDS, HashLength*sizeof(uint8_t));
    for (r=0; r<NUM_ROUNDS; r++) {
        keccak((uint8_t*) sig->Randoms[r], obytes, sig->HashResp+((2*r)*HashLength), HashLength);
        keccak((uint8_t*) sig->psiS[r], sizeof(point_proj), sig->HashResp+((2*r+1)*HashLength), HashLength);
    }

    // Create challenge hash (by hashing all the commitments and HashResps)
    uint8_t *datastring, *cHash;
    int DataLength = (2 * NUM_ROUNDS * 2*pbytes) + (2 * NUM_ROUNDS * HashLength*sizeof(uint8_t));
    int cHashLength = NUM_ROUNDS/8;
    datastring = calloc(1, DataLength);
    cHash = calloc(1, cHashLength);

    //print_hash(cHash);
    
    hashdata(pbytes, sig->Commitments1, sig->Commitments2, sig->HashResp, HashLength, DataLength, datastring, cHash, cHashLength);

    //printf("\nChallenge hash: ");
    //print_hash(cHash, cHashLength);

    //printf("\nhashed\n");


    
cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}



typedef struct thread_params_verify {
	PCurveIsogenyStruct *CurveIsogeny;
	unsigned char *PublicKey;
	struct Signature *sig;

	int cHashLength;
	uint8_t *cHash;
	
	unsigned int pbytes;
	unsigned int n;
	unsigned int obytes;
} thread_params_verify;

void *verify_thread(void *TPV) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	thread_params_verify *tpv = (thread_params_verify*) TPV;

	// iterate through cHash bits as challenge and verify
    bool verified = true;
    int r=0;
    int i,j;

    while (1) {
    	int stop=0;

		pthread_mutex_lock(&RLOCK);
		if (CUR_ROUND >= NUM_ROUNDS) {
			stop=1;
		} else {
			r = CUR_ROUND;
			CUR_ROUND++;
		}
		pthread_mutex_unlock(&RLOCK);

		if (stop) break;

		//printf("\nround: %d ", CUR_ROUND);
		i = r/8;
		j = r%8;

		int bit = tpv->cHash[i] & (1 << j);  //challenge bit

		if (bit == 0) {
            //printf("round %d: bit 0 - ", r);

            // Check R, phi(R) has order 2^372 (suffices to check that the random number is even)
            uint8_t lastbyte = ((uint8_t*) tpv->sig->Randoms[r])[0];
            if (lastbyte % 2) {
                printf("ERROR: R, phi(R) are not full order\n");
            } else {
                //printf("checked order. ");
            }

            // Check kernels
            f2elm_t A;
            unsigned char *TempPubKey;
            TempPubKey = (unsigned char*)calloc(1, 4*2*tpv->pbytes);
            
            Status = KeyGeneration_A(tpv->sig->Randoms[r], TempPubKey, *(tpv->CurveIsogeny), false);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E -> E/<R> failed");
            }
            
            to_fp2mont(((f2elm_t*)TempPubKey)[0], A);

            int cmp = memcmp(A, tpv->sig->Commitments1[r], sizeof(f2elm_t));
            if (cmp != 0) {
                verified = false;
                printf("verifying E -> E/<R> failed\n");
            }
            

            unsigned char *TempSharSec;
            TempSharSec = (unsigned char*)calloc(1, 2*tpv->pbytes);

            Status = SecretAgreement_A(tpv->sig->Randoms[r], tpv->PublicKey, TempSharSec, *(tpv->CurveIsogeny), NULL);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E/<S> -> E/<R,S> failed");
            }

            cmp = memcmp(TempSharSec, tpv->sig->Commitments2[r], 2*tpv->pbytes);
            if (cmp != 0) {
                verified = false;
                printf("verifying E/<S> -> E/<R,S> failed\n");
            }

        } else {
            //printf("round %d: bit 1 - ", r);

            // Check psi(S) has order 3^239 (need to triple it 239 times)
            point_proj_t triple = {0};
            copy_words((digit_t*)tpv->sig->psiS[r], (digit_t*)triple, 2*2*NWORDS_FIELD);

            f2elm_t A,C={0};
            to_fp2mont(((f2elm_t*)tpv->PublicKey)[0],A);
            fpcopy751((*(tpv->CurveIsogeny))->C, C[0]);
            int t;
            for (t=0; t<238; t++) {
                xTPL(triple, triple, A, C);
                if (is_felm_zero(((felm_t*)triple->Z)[0]) && is_felm_zero(((felm_t*)triple->Z)[1])) {
                    printf("ERROR: psi(S) has order 3^%d\n", t+1);
                }
            }

            unsigned char *TempSharSec, *TempPubKey;
            TempSharSec = calloc(1, 2*tpv->pbytes);
            TempPubKey = calloc(1, 4*2*tpv->pbytes);
            from_fp2mont(tpv->sig->Commitments1[r], ((f2elm_t*)TempPubKey)[0]);

            Status = SecretAgreement_B(NULL, TempPubKey, TempSharSec, *(tpv->CurveIsogeny), tpv->sig->psiS[r], NULL);
            if(Status != CRYPTO_SUCCESS) {
                printf("Computing E/<R> -> E/<R,S> failed");
            }

            int cmp = memcmp(TempSharSec, tpv->sig->Commitments2[r], 2*tpv->pbytes);
            if (cmp != 0) {
                verified = false;
                printf("verifying E/<R> -> E/<R,S> failed\n");
            }
        }
    }

    if (!verified) {
    	printf("ERROR: verify failed.\n");
	    //printf("Average time for verification per round ...... %10lld cycles\n", totcycles/NUM_ROUNDS);
    }
}


CRYPTO_STATUS isogeny_verify(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PublicKey, struct Signature *sig) {
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2, totcycles=0;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    int r;

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        //goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        //goto cleanup;
    }

    // compute challenge hash
    int HashLength = 32;
    int cHashLength = NUM_ROUNDS/8;
    int DataLength = (2 * NUM_ROUNDS * 2*pbytes) + (2 * NUM_ROUNDS * HashLength*sizeof(uint8_t));
    uint8_t *datastring, *cHash;
    datastring = calloc(1, DataLength);
    cHash = calloc(1, cHashLength);

    hashdata(pbytes, sig->Commitments1, sig->Commitments2, sig->HashResp, HashLength, DataLength, datastring, cHash, cHashLength);


    // Run the verifying rounds
    pthread_t verify_threads[NUM_THREADS];
    CUR_ROUND = 0;
    if (pthread_mutex_init(&RLOCK, NULL)) {
    	printf("ERROR: mutex init failed\n");
    	return 1;
    }
    thread_params_verify tpv = {&CurveIsogeny, PublicKey, sig, cHashLength, cHash, pbytes, n, obytes};

    int t;
    for (t=0; t<NUM_THREADS; t++) {
    	if (pthread_create(&verify_threads[t], NULL, verify_thread, &tpv)) {
    		printf("ERROR: Failed to create thread %d\n", t);
    	}
    }

    for (t=0; t<NUM_THREADS; t++) {
    	pthread_join(verify_threads[t], NULL);
  	}



    


cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}







// Optional parameters: #threads, #rounds
int main(int argc, char *argv[])
{
	NUM_THREADS = 1;

	if (argc > 1) {
		NUM_THREADS = atoi(argv[1]);
	}

	printf("NUM_THREADS: %d\n", NUM_THREADS);




    CRYPTO_STATUS Status = CRYPTO_SUCCESS;


/*
    Status = cryptotest_kex(&CurveIsogeny_SIDHp751);       // Test elliptic curve isogeny system "SIDHp751"
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }

    Status = cryptorun_kex(&CurveIsogeny_SIDHp751);        // Benchmark elliptic curve isogeny system "SIDHp751"
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }

    Status = cryptotest_BigMont(&CurveIsogeny_SIDHp751);   // Test elliptic curve "BigMont"
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }

    Status = cryptorun_BigMont(&CurveIsogeny_SIDHp751);    // Benchmark elliptic curve "BigMont"
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
        return false;
    }
*/



    int rep;
    for (rep=0; rep<10; rep++) {

        Status = cryptotest_kex(&CurveIsogeny_SIDHp751);       // Test elliptic curve isogeny system "SIDHp751"
        if (Status != CRYPTO_SUCCESS) {
            printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
            return false;
        }

        Status = cryptorun_kex(&CurveIsogeny_SIDHp751);        // Benchmark elliptic curve isogeny system "SIDHp751"
        if (Status != CRYPTO_SUCCESS) {
            printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
            return false;
        }

        printf("\n\nBENCHMARKING SIGNATURE run %d:\n", rep+1);


        unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;      // Number of bytes in a field element 
        unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;   // Number of bytes in an element in [1, order]
        unsigned long long cycles1, cycles2, kgcycles, scycles, vcycles;

        // Allocate space for keys
        unsigned char *PrivateKey, *PublicKey;
        PrivateKey = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
        PublicKey = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)

        struct Signature sig;




        cycles1 = cpucycles();
        Status = isogeny_keygen(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey);
        if (Status != CRYPTO_SUCCESS) {
            printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
            return false;
        }
        cycles2 = cpucycles();
        kgcycles = cycles2 - cycles1;

        cycles1 = cpucycles();
        Status = isogeny_sign(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, &sig);
        if (Status != CRYPTO_SUCCESS) {
            printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
            return false;
        }
        cycles2 = cpucycles();
        scycles = cycles2 - cycles1;

        cycles1 = cpucycles();
        Status = isogeny_verify(&CurveIsogeny_SIDHp751, PublicKey, &sig);
        if (Status != CRYPTO_SUCCESS) {
            printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
            return false;
        }
        cycles2 = cpucycles();
        vcycles = cycles2 - cycles1;

        printf("KeyGen ............. %10lld cycles\n", kgcycles);
        printf("Signing ............ %10lld cycles\n", scycles);
        printf("Verifying .......... %10lld cycles\n\n", vcycles);


        clear_words((void*)PrivateKey, NBYTES_TO_NWORDS(obytes));
        clear_words((void*)PublicKey, NBYTES_TO_NWORDS(4*2*pbytes));



/*
        Status = cryptotest_BigMont(&CurveIsogeny_SIDHp751);   // Test elliptic curve "BigMont"
        if (Status != CRYPTO_SUCCESS) {
            printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
            return false;
        }

        Status = cryptorun_BigMont(&CurveIsogeny_SIDHp751);    // Benchmark elliptic curve "BigMont"
        if (Status != CRYPTO_SUCCESS) {
            printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
            return false;
        }
*/

    }

    

    return true;
}




