#include <openssl/opensslconf.h>

#include <stdio.h>
#include <string.h>


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

int mecs_init() {
    	printf("McEliece Engine Initializatzion!\n");

    	int rc = 0;

        // MUST BE NULL
    	BPU_T_Mecs_Ctx *ctx = NULL;
        BPU_T_UN_Mecs_Params params;


        /***************************************/
        // mce initialisation t = 50, m = 11
        fprintf(stderr, "Basic GOPPA Initialisation...\n");
        if (BPU_mecsInitParamsGoppa(&params,13 , 119, 0x2129)) {
    //    if (BPU_mecsInitParamsGoppa(&params,11 , 50,  0)) {
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

static int char2gf2Vec(const unsigned char *from, int w, BPU_T_GF2_Vector *to){
    int i,j;
    for(i = 0; i < w; i++) {
    	    for(j = 0; j<8; j++){
    	    	BPU_gf2VecSetBit(to, (8*i)+(j),  ((*(from+i) >> j) & 0x01));
    	   // 	BPU_gf2VecSetBit(to, 8*i+j, j);
    	   // 	printf("%i", BPU_gf2VecGetBit(to, ((8*i)+j )));
    	    }
    }
    return 0;
}

static int gf2Vec2char(BPU_T_GF2_Vector *fromm, int w, unsigned char  *to){
//	to= malloc(w + 1);
    int i,j;
    char temp;
    for(i = 0; i < w; i++) {
    	temp=0;
    	    for(j = 0; j<8; j++){
    	   // 	temp|= BPU_gf2VecGetBit(from, (8*i)+j )>>j);
    	  //  	temp |= 1 >>j;
    	    	temp|= BPU_gf2VecGetBit(fromm, (8*i)+j)<<j;
    	    }
    	   //  	printf("%c",temp);
    	     	to[i]=temp;
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
	      // prepare plain text, allocate memory and init plaintext
	      if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
	          BPU_printError("PT initialisation error");
	          BPU_gf2VecFree(&pt);
	          return 1;
	      }

	      char2gf2Vec(from,len,pt);


	      // alocate cipher text vector
	      if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
	          BPU_printError("CT vector allocation error");
	          BPU_gf2VecFree(&pt);
	          BPU_gf2VecFree(&ct);
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


	      gf2Vec2char(ct,ctx->ct_len/8,to);
          BPU_gf2VecFree(&ct);
          BPU_gf2VecFree(&pt);

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
      // prepare cipher text, allocate memory and init ciphertext
      if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
          BPU_printError("CT initialisation error");
          BPU_gf2VecFree(&ct);
          return 1;
      }
      char2gf2Vec(from,len,ct);

      // alocate cipher text vector
      if (BPU_gf2VecMalloc(&pt, ctx->pt_len)) {
          BPU_printError("PT vector allocation error");
          BPU_gf2VecFree(&pt);
          BPU_gf2VecFree(&ct);
          return 1;
      }
      /***************************************/
      fprintf(stderr, "Decryption...\n");
	  // decrypt cipher text
	  if (BPU_mecsDecrypt(pt, ct, ctx)) {
		  BPU_printError("Decryption error");

		  BPU_gf2VecFree(&ct);
		  BPU_gf2VecFree(&pt);
		  return 1;
	  }
      /***************************************/


  gf2Vec2char(pt,len,to);
  BPU_gf2VecFree(&ct);
  BPU_gf2VecFree(&pt);

return(ctx->pt_len);
}


int main(int argc, const char* argv[] ) {
	mecs_init();
	int len =4;
	int outlen=-1;
	int rc = 0;
//	BPU_T_Mecs_Ctx *ctx = NULL;
//    BPU_T_GF2_Vector *ct, *pt;
//    BPU_gf2VecMalloc(&pt,len*8);
	 const unsigned char *fromm="JOJO";
	  unsigned char *to=malloc(1025);
	  RSA rsa;
	  unsigned char * copy = malloc(1025);

	//  unsigned char * copy;
	//  strcpy(copy, "HHHH");
	//  strcpy(to, "AHOJ");
	  outlen = public_encrypt(len, fromm, copy, &rsa, 50)/8;

	  printf("%s",fromm);
	  printf("\n");
	  printf("%s\n",copy);

	  private_decrypt(outlen,copy,to, &rsa, 50);
	  printf("%i,\n",outlen);
//	  char2gf2Vec(fromm,len,pt);
//	  gf2Vec2char(pt,4,to);


	  printf("\n");
	  printf("%s",to);
    return 0;
}
