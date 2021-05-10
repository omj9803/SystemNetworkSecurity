/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char optionPlaintext[100] = "/root/";
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encryptedkey[1] = {0};
	char decryptedkey[2] = {0,0};
	int len = 64;


	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	if(strcmp(argv[1],"-e") == 0){
		printf("========================Encryption========================\n");
		strcat(optionPlaintext, argv[2]);
		FILE *fp_read = fopen(optionPlaintext,"r");
		fgets(plaintext, sizeof(plaintext), fp_read);
		fclose(fp_read);
		printf("Plaintext : %s\n", plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
					 &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Ciphertext : %s", ciphertext);
		FILE *fp_write = fopen("/root/ciphertext.txt","w");
		fputs(ciphertext, fp_write);

		memcpy(op.params[0].tmpref.buffer, encryptedkey, 1);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
					 &err_origin);
		memcpy(encryptedkey, op.params[0].tmpref.buffer, 1);
		//printf("encryptedkey is %c\n", encryptedkey[0]);
		fputc(encryptedkey[0], fp_write);
		fclose(fp_write);
		printf("==========================================================\n");
	}

	else if(strcmp(argv[1],"-d") == 0){
		printf("========================Decryption========================\n");
		strcat(optionPlaintext, argv[2]);
		FILE *fp_read_ci = fopen(optionPlaintext,"r");
		fgets(ciphertext, sizeof(ciphertext), fp_read_ci);
		fgets(decryptedkey, sizeof(decryptedkey), fp_read_ci);
		printf("Ciphertext : %s\n", ciphertext);
		//printf("decryptedkey : %s\n", decryptedkey);

		memcpy(op.params[0].tmpref.buffer, decryptedkey, 1);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op,
					 &err_origin);
		memcpy(decryptedkey, op.params[0].tmpref.buffer, 1);
		//printf("decryptedkey is : %d\n", decryptedkey);
	
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s", plaintext);
		FILE *fp_write_pl = fopen("/root/plaintext.txt","w");
		fputs(plaintext, fp_write_pl);
		printf("===========================================================\n");
	}


	

	
	
	
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
