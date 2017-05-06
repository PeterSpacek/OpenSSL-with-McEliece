#include <openssl/opensslconf.h>

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>

#include <openssl/bn.h>
#include <openssl/err.h>


#include <bitpunch/bitpunch.h>
#include <bitpunch/tools.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <bitpunch/crypto/hash/sha512.h>
#include <bitpunch/asn1/asn1.h>
#include "libtasn1.h"
#include <bitpunch/math/bigint.h>
#include <bitpunch/math/uni.h>


#define NID_id_Mecs_1	0x2129
#define NID_id_Mecs_2	0

static const char *engine_id ="bpMECS";
static const char *engine_name ="BitPuch McEliece implementation for OpenSSL";


static int mecs_pkey_meth_nids[] = {
        NID_id_Mecs_1,
        0
};

int mecs_init(ENGINE *e) {
	printf("McEliece Engine Initializatzion!\n");

	int rc = 0;

    // MUST BE NULL
	BPU_T_Mecs_Ctx *ctx = NULL;
    BPU_T_UN_Mecs_Params params;


    /***************************************/
    // mce initialisation t = 50, m = 11
    fprintf(stderr, "Basic GOPPA Initialisation...\n");
    if (BPU_mecsInitParamsGoppa(&params,13 , 119, 0x2129)) {
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
static int Vec2char(const unsigned char *from, int w, unsigned char  *to){

    int i,j;
    char temp;
    for(i = 0; i < w; i++) {

    	     	to[i]=from[i];
    }

    return 0;
}

/* encrypt */
static int mecs_encrypt(EVP_PKEY_CTX *pctx, unsigned char *to, size_t *outlen,  const unsigned char *from, size_t inlen){
	//	int outlen=-1;
		int rc = 0;
		BPU_T_Mecs_Ctx *ctx = NULL;
	    BPU_T_GF2_Vector *ct=NULL, *pt=NULL;
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

	      char2gf2Vec(from,inlen,pt);


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

	      *outlen=ctx->ct_len/8;
	      gf2Vec2char(ct,ctx->ct_len,to);
          BPU_gf2VecFree(&ct);
          BPU_gf2VecFree(&pt);

	return *outlen;
}

/* decrypt */
//static int mecs_decrypt(EVP_PKEY_CTX pctx, int len, const unsigned char *from, unsigned char *to, RSA *rsa, int padding){
static int mecs_decrypt(EVP_PKEY_CTX * pctx, const unsigned char *from, size_t inlen, unsigned char *to,  size_t *outlen){
	//int outlen=-1;
	int rc = 0;
	BPU_T_Mecs_Ctx *ctx = NULL;
    BPU_T_GF2_Vector *ct=NULL, *pt=NULL;
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
      char2gf2Vec(from,inlen,ct);

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


  gf2Vec2char(pt,ctx->pt_len,to);
  BPU_gf2VecFree(&ct);
  BPU_gf2VecFree(&pt);
  *outlen=ctx->pt_len;
  	return *outlen/8;
}

static RSA_METHOD mecs2 =
{
		 /* name of the implementation */
		  "McEliece",

		    /* encrypt */
		  mecs_encrypt,

		    /* verify arbitrary data */
		  NULL,
		    /* sign arbitrary data */
		  NULL,

		    /* decrypt */
		  mecs_decrypt,

		    /* compute r0 = r0 ^ I mod rsa->n (May be NULL for some
		                                       implementations) */
		  NULL,

		    /* compute r = a ^ p mod m (May be NULL for some implementations) */
		  NULL,

		    /* called at RSA_new */
		  NULL,

		    /* called at RSA_free */
		  NULL,
		  /* RSA_FLAG_EXT_PKEY        - rsa_mod_exp is called for private key
		      *                            operations, even if p,q,dmp1,dmq1,iqmp
		      *                            are NULL
		      * RSA_FLAG_SIGN_VER        - enable rsa_sign and rsa_verify
		      * RSA_METHOD_FLAG_NO_CHECK - don't check pub/private match
		      */
		  0,

		  NULL,

		     /* sign. For backward compatibility, this is used only
		      * if (flags & RSA_FLAG_SIGN_VER)
		      */
		  NULL,

		     /* verify. For backward compatibility, this is used only
		      * if (flags & RSA_FLAG_SIGN_VER)
		      */
		  NULL
};

static EVP_PKEY_METHOD *mecs_pmeth= NULL;

	static void pkey_free_mecs(EVP_PKEY *key)
		{

		/*
		if (key->pkey.ec)
			{
			EC_KEY_free(key->pkey.ec);
			}
			*/
		}

	static int mecs_pkey_meths(ENGINE* e, EVP_PKEY_METHOD** meth,
                                const int** nids, int nid) {
    if (meth == NULL) {
        *nids = mecs_pkey_meth_nids;
        return sizeof(mecs_pkey_meth_nids) / sizeof(mecs_pkey_meth_nids[0]) - 1;
    }

    switch (nid) {
        case NID_id_Mecs_1:
         //   *meth = mecs_meth;
            return 1;

        default:;
    }

    *meth = NULL;
    return 0;
}
	/*
	int register_ameth_mecs (int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info)
		{
		*ameth =	EVP_PKEY_asn1_new(nid,
			ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
		if (!*ameth) return 0;
		switch (nid)
			{
			case NID_id_Mecs_1:
				EVP_PKEY_asn1_set_free (*ameth, pkey_free_mecs);
				EVP_PKEY_asn1_set_private (*ameth,
					priv_decode_mecs, priv_encode_mecs,
					priv_print_mecs);
				EVP_PKEY_asn1_set_param (*ameth,
						mecs_param_decode, mecs_param_encode,
					param_missing_mecs, param_copy_mecs,
					param_cmp_mecs,param_print_mecs );
				EVP_PKEY_asn1_set_public (*ameth,
					pub_decode_mecs, pub_encode_mecs,
					pub_cmp_mecs, pub_print_mecs,
					pkey_size_mecs, pkey_bits_mecs);

				EVP_PKEY_asn1_set_ctrl (*ameth, pkey_ctrl_mecs);
				break;
			}
		return 1;
		}
		*/



int register_pmeth_mecs(int id, EVP_PKEY_METHOD **pmeth, int flags){
//	mecs_pkey_meths=
	*pmeth = EVP_PKEY_meth_new(id, flags);
	if (!*pmeth)
	     return 0;
	EVP_PKEY_meth_set_encrypt(pmeth,NULL,mecs_encrypt);
	EVP_PKEY_meth_set_decrypt(pmeth,NULL,mecs_decrypt);

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
/*
      if (!ENGINE_set_pkey_asn1_meths(e, mecs_pkey_meths)) {
          printf("ENGINE_set_pkey_meths failed\n");
          return 0;
      }
      */
      /*
      // const RSA_METHOD *meth1;
      if (!ENGINE_set_RSA(e, &mecs)	) {
        printf("ENGINE_init_function failed\n");
        return 0;
      }
*/

      if (!register_pmeth_mecs(NID_id_Mecs_1, &mecs_pmeth, 0))
      return 0;


    }


IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()



