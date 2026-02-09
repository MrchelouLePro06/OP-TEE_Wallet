#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>
#include <small_app_ta.h>

static void read_file(const char *filename, char *buffer, size_t *size) {
	FILE *f = fopen(filename, "rb");
	if (!f)
    	errx(1, "Failed to open input file: %s", filename);
	
	*size = fread(buffer, 1, MAX_BUFFER_SIZE, f);
	if (*size == 0)
        errx(1, "Failed to read from file or file is empty");
	fclose(f);
}

static void write_file(const char *filename, char *buffer, size_t size) {
	FILE *f = fopen(filename, "wb");
	if (!f)
        errx(1, "Failed to open output file: %s", filename);
	
	size_t written = fwrite(buffer, 1, size, f);
	if (written != size)
        errx(1, "Failed to write to file");
	fclose(f);	
}

static void generate_key(TEEC_Session *sess) {
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	res = TEEC_InvokeCommand(sess, TA_SMALL_APP_CMD_GENERATE_KEY,&op, &err_origin);
	if (res != TEEC_SUCCESS){
		errx(1, "Failed to generate key: 0x%x origin 0x%x", res, err_origin);}
	printf("Key successfully generated and stored\n");
}

static void encrypt_file(TEEC_Session *sess, const char *input_file,const char *output_file) {
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	char in_buffer[MAX_BUFFER_SIZE];
	char out_buffer[MAX_BUFFER_SIZE + 16]; // Extra space for IV size_t file_size;
	size_t file_size;
	
	// Read input file
	read_file(input_file, in_buffer, &file_size);
	printf("Read %zu bytes from %s\n", file_size, input_file);
	
	// Prepare operation
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE,TEEC_NONE);
	op.params[0].tmpref.buffer = in_buffer;
	op.params[0].tmpref.size = file_size;
	op.params[1].tmpref.buffer = out_buffer;
	op.params[1].tmpref.size = sizeof(out_buffer);
	
	// Encrypt data
	printf("Encrypting data...\n");
	res = TEEC_InvokeCommand(sess, TA_SMALL_APP_CMD_ENCRYPT, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		    errx(1, "Failed to encrypt data: 0x%x origin 0x%x", res, err_origin);
	
	// Write output file
	write_file(output_file, out_buffer, op.params[1].tmpref.size);
	printf("Wrote %zu bytes to %s\n", op.params[1].tmpref.size, output_file);
}

static void decrypt_file(TEEC_Session *sess, const char *input_file,const char *output_file) {
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	char in_buffer[MAX_BUFFER_SIZE];
	char out_buffer[MAX_BUFFER_SIZE];
	size_t file_size;
	
	// Read input file
	read_file(input_file, in_buffer, &file_size);
	printf("Read %zu bytes from %s\n", file_size, input_file);
	
	// Prepare operation
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE,TEEC_NONE);
	op.params[0].tmpref.buffer = in_buffer;
	op.params[0].tmpref.size = file_size;
	op.params[1].tmpref.buffer = out_buffer;
	op.params[1].tmpref.size = sizeof(out_buffer);
	
	// Decrypt data
	printf("Decrypting data...\n");
	res = TEEC_InvokeCommand(sess, TA_SMALL_APP_CMD_DECRYPT, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		    errx(1, "Failed to decrypt data: 0x%x origin 0x%x", res, err_origin);
	
	// Write output file
	write_file(output_file, out_buffer, op.params[1].tmpref.size);
	printf("Wrote %zu bytes to %s\n", op.params[1].tmpref.size, output_file);	
}

int main(int argc, char* argv[]) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_SMALL_APP_UUID;
    uint32_t err_origin;
    // Check command line arguments
    if (argc < 2) {
            printf("Usage:\n");
            printf("  %s generate-key\n", argv[0]);
            printf("  %s encrypt <input_file> <output_file>\n", argv[0]);
            printf("  %s decrypt <input_file> <output_file>\n", argv[0]);
            return 1;
	}
	
	// Initialize context
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
            errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
    // Open session
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
                NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
            errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x\n",
                        res, err_origin);
    // Process commands
    if (strcmp(argv[1], "generate-key") == 0) {
            generate_key(&sess);
    }
 	else if (strcmp(argv[1], "encrypt") == 0) {
 		if (argc != 4) {
           errx(1, "Encryption requires input and output file arguments");
        }
		encrypt_file(&sess, argv[2], argv[3]);
	}
	else if (strcmp(argv[1], "decrypt") == 0) {
		if (argc != 4) {
			errx(1, "Decryption requires input and output file arguments");
		}
		decrypt_file(&sess, argv[2], argv[3]);
	}
	else{
		errx(1, "Unknown command: %s", argv[1]);
	}
	
	// Cleanup
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
