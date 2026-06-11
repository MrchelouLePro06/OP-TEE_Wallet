#include <err.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>

#include <test_passt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op = {0};
	TEEC_UUID uuid = TA_TEST_PASST_UUID;
	uint32_t err_origin;

	if (argc < 3 || strcmp(argv[1], "confirm_rcv") != 0) {
		fprintf(stderr, "Usage: %s confirm_rcv <message>\n", argv[0]);
		return 1;
	}

	char *msg_to_sign = argv[2];
	uint8_t signature[256]; // Taille pour RSA-2048

	/* Initialiser le contexte TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed 0x%x", res);

	/* Ouvrir la session avec la TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x", res, err_origin);

	/* Préparer l'opération pour la TA */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	// Paramètre [0] : Le message texte du client
	op.params[0].tmpref.buffer = msg_to_sign;
	op.params[0].tmpref.size = strlen(msg_to_sign);

	// Paramètre [1] : Le buffer pour recevoir la signature
	op.params[1].tmpref.buffer = signature;
	op.params[1].tmpref.size = sizeof(signature);

	/* Appeler la commande confirm_reception dans la TA */
	res = TEEC_InvokeCommand(&sess, TA_TEST_PASST_CMD_CONF, &op, &err_origin);
	
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InvokeCommand failed 0x%x origin 0x%x\n", res, err_origin);
	} else {
		/* Afficher la signature en hexadécimal pour le script Python */
		for (size_t i = 0; i < op.params[1].tmpref.size; i++) {
			printf("%02x", signature[i]);
		}
		printf("\n");
	}

	/* Nettoyage */
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
