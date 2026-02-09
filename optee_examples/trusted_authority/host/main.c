#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* OP-TEE TEE client API (built by optee_client) */ 
#include <tee_client_api.h>
/* For the UUID (found in the TA's h-file(s)) */ 
#include <trusted_authority_ta.h>

void usage(const char *app_name) {
    fprintf(stderr, "Usage: %s store <name> <age>\n", app_name);
    fprintf(stderr, "   or: %s check <name>\n", app_name);
    exit(1);
}

int main(int argc, char *argv[]) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_TRUSTED_AUTHORITY_UUID;
    uint32_t err_origin;
    if (argc < 2) {
        usage(argv[0]);
	}
	
	// Initialize TEE Context
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
    }

	// Open a session with the TA
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,&err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res,err_origin);
    }
    
	memset(&op, 0, sizeof(op));
	
	if (strcmp(argv[1], "store") == 0) { 
		if(argc!=4){
		    usage(argv[0]);
		}
		const char *name = argv[2];
		uint32_t age = atoi(argv[3]);
	
		if (age == 0 && strcmp(argv[3], "0") != 0) { // Basic check for valid integer
	  		warnx("Invalid age: %s", argv[3]);
		 	usage(argv[0]);
		}
		
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE, TEEC_NONE);
                                     
   		op.params[0].tmpref.buffer = (void *)name;
		op.params[0].tmpref.size = strlen(name) + 1; // Include null terminator 
		op.params[1].value.a = age;
		
		printf("Invoking TA to store: Name='%s', Age=%u\n", name, age);
		res = TEEC_InvokeCommand(&sess, CMD_STORE_WALLET_DATA, &op, &err_origin);
		if (res != TEEC_SUCCESS) {
			errx(1, "TEEC_InvokeCommand(STORE_WALLET_DATA) failed with code 0x%x , origin 0x%x", res, err_origin);
		}
		printf("Data stored successfully.\n");
		
	} else if (strcmp(argv[1], "check") == 0) { 
		if(argc!=3){
        	usage(argv[0]);
    	}
    	const char *name = argv[2];
    	if (strlen(name) >= MAX_NAME_LEN) {
        	warnx("Name '%s' is too long (max %d chars).", name, MAX_NAME_LEN -1);
        	usage(argv[0]);
    	}
    	
    	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    	op.params[0].tmpref.buffer = (void *)name;
		op.params[0].tmpref.size = strlen(name) + 1; // Include null terminator
		
		printf("Invoking TA to check age for: Name='%s'\n", name);
		res = TEEC_InvokeCommand(&sess, CMD_CHECK_AGE, &op, &err_origin);
		if (res != TEEC_SUCCESS) {
			errx(1, "TEEC_InvokeCommand(CHECK_AGE) failed with code 0x%x origin ,→ 0x%x", res, err_origin);
		}
		
		// Output "true" or "false" for easy parsing by Python
         if (op.params[1].value.a == 1) {
             printf("true\n");
         } else {
             printf("false\n");
			}
	} else {
		usage(argv[0]);
	}
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}

