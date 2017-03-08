#include <openssl/opensslconf.h>

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>

#include <openssl/bn.h>
#include <openssl/err.h>


#include <bitpunch/bitpunch.h>
#include "bitpunch/tools.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <bitpunch/crypto/hash/sha512.h>
#include <bitpunch/asn1/asn1.h>
#include <libtasn1.h>
#include <bitpunch/math/bigint.h>
#include <bitpunch/math/uni.h>

static const char *engine_id ="bpMECS";
static const char *engine_name ="BitPuch McEliece implementation for OpenSSL";

int mecs_init(ENGINE *e) {
    	printf("McEliece Engine Initializatzion!\n");

    	int rc = 0;

        // MUST BE NULL
    	BPU_T_Mecs_Ctx *ctx = NULL;
        BPU_T_UN_Mecs_Params params;

        /***************************************/
        // mce initialisation t = 50, m = 11
        fprintf(stderr, "Basic GOPPA Initialisation...\n");
        if (BPU_mecsInitParamsGoppa(&params, 11, 50, 0)) {
            return 1;
        }

        if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_BASIC_GOPPA)) {
  //    if (BPU_mecsInitCtx(&ctx, 11, 50, BPU_EN_MECS_CCA2_POINTCHEVAL_GOPPA)) {
            return 1;
        }
        /***************************************/
        fprintf(stderr, "Key generation...\n");
        // key pair generation
        if (BPU_mecsGenKeyPair(ctx)) {
            BPU_printError("Key generation error");
            return 1;
        }
        rc = BPU_asn1SaveKeyPair(ctx, "prikey.der", "pubkey.der");
            if (rc) {
                asn1_perror(rc);
            }
        BPU_mecsFreeCtx(&ctx);
        BPU_mecsFreeParamsGoppa(&params);

    return 786;
}

static RSA_METHOD mecs =
{
  "McEliece",
  /* encrypt */
  public_encrypt,
  NULL,
  NULL,
  /* decrypt */
  private_decrypt,
  NULL,
  NULL,
  NULL,
  NULL,
  0,
  NULL,
  NULL,
  NULL
};

static int BPU_gf2VecRand(const unsigned char *from, int w, BPU_T_GF2_Vector *to){
    int i,j;

    BPU_gf2VecNull(to);

    for(i = 0; i < w; i++) {
    	    for(j = 7; 0 <= j; j --)
    	    	BPU_gf2VecSetBit(to, 8*i+(7-j),  ((byte >> j) & 0x01)));
    }

         return 0;
}

/* encrypt */
static int public_encrypt(int len, const unsigned char *from, unsigned char *to, RSA *rsa, int padding){
		int outlen=-1;
		int rc = 0;
		BPU_T_Mecs_Ctx *ctx = NULL;
	    BPU_T_GF2_Vector *ct, *pt;
		rc = BPU_asn1LoadKeyPair(&ctx, "prikey.der", "pubkey.der");
	    if (rc) {
	        asn1_perror(rc);
	    }


	    /***************************************/
	      // prepare plain text, allocate memory and init random plaintext
	      if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
	          BPU_printError("PT initialisation error");
	          return 1;
	      }
	      BPU_gf2VecRand(pt, 0);

	      // alocate cipher text vector
	      if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
	          BPU_printError("CT vector allocation error");

	          BPU_gf2VecFree(&pt);
	          return 1;
	      }
	          /***************************************/
	      fprintf(stderr, "Encryption...\n");
	      // BPU_encrypt plain text
	      if (BPU_mecsEncrypt(ct, pt, ctx)) {
	          BPU_printError("Encryption error");

	          BPU_gf2VecFree(&ct);
	          BPU_gf2VecFree(&pt);
	          return 1;
	      }




	return(ctx->ct_len);
}

/* decrypt */
static int private_decrypt(int len, const unsigned char *from, unsigned char *to, RSA *rsa, int padding){
	int outlen=-1;
	int rc = 0;
	BPU_T_Mecs_Ctx *ctx = NULL;
    BPU_T_GF2_Vector *ct, *pt;
	rc = BPU_asn1LoadKeyPair(&ctx, "prikey.der", "pubkey.der");
    if (rc) {
        asn1_perror(rc);
    }


    /***************************************/
      // prepare plain text, allocate memory and init random plaintext
      if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
          BPU_printError("PT initialisation error");
          return 1;
      }
      BPU_gf2VecRand(pt, 0);

      // alocate cipher text vector
      if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
          BPU_printError("CT vector allocation error");

          BPU_gf2VecFree(&pt);
          return 1;
      }
      /***************************************/
  fprintf(stderr, "Decryption...\n");
  // decrypt cipher text
  if (BPU_mecsDecrypt(pt, ct, ctx)) {
      BPU_printError("Decryption error");

      BPU_gf2VecFree(&ct);
      BPU_gf2VecFree(&pt);
      BPU_gf2VecFree(&pt);
      return 1;
  }
      /***************************************/




return(ctx->pt_len);
}

static int bind(ENGINE *e, const char *id)
    {

	  if (!ENGINE_set_id(e, engine_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        return 0;
      }
      if (!ENGINE_set_name(e, engine_name)) {
        printf("ENGINE_set_name failed\n");
        return 0;
      }
      if (!ENGINE_set_init_function(e,mecs_init)) {
        printf("ENGINE_init_function failed\n");
        return 0;
      }
     // const RSA_METHOD *meth1;

      if (!ENGINE_set_RSA(e, &mecs)	) {
        printf("ENGINE_init_function failed\n");
        return 0;
      }

      return 1;

    }


IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()



