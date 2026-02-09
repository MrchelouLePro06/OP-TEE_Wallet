#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <small_app_ta.h>

static TEE_ObjectHandle stored_key = TEE_HANDLE_NULL;

static TEE_Result generate_and_store_key(void) {
	TEE_Result res;
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;
	uint8_t key_buffer[32]; // for 256-bit key
	
	// Generate random key
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, KEY_SIZE, &key);
	
	if (res != TEE_SUCCESS) {
		IMSG("Error while allocating transient object for key generation: 0x%x\n", res);
		if (key != TEE_HANDLE_NULL)
       		TEE_FreeTransientObject(key);
		return res;
	}
	
	res = TEE_GenerateKey(key, KEY_SIZE, NULL, 0);
	if (res != TEE_SUCCESS) {
		IMSG("Error while generating key: 0x%x\n", res);
		if (key != TEE_HANDLE_NULL)
		    TEE_FreeTransientObject(key);
	return res;
	}
	
	// Create persistent object (in Trusted Storage Space)
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,KEY_STORAGE_ID, strlen(KEY_STORAGE_ID),
                                TEE_DATA_FLAG_ACCESS_READ |
                                TEE_DATA_FLAG_ACCESS_WRITE |
                                TEE_DATA_FLAG_ACCESS_WRITE_META,
                                TEE_HANDLE_NULL,
                                NULL, 0,
                                &persistent_key);
	if (res != TEE_SUCCESS) {
		 IMSG("Error while creating persistent object for Trusted Storage: 0x%x\n", res);
		if (key != TEE_HANDLE_NULL)
				TEE_FreeTransientObject(key);
		if (persistent_key != TEE_HANDLE_NULL)
				TEE_CloseObject(persistent_key);
		return res;
	}
	
	// Extract key material
	uint32_t key_size = sizeof(key_buffer);
	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE,
		                                            key_buffer, &key_size);
	if (res != TEE_SUCCESS) {
		IMSG("Error while extracting key: 0x%x\n", res);
	    if (key != TEE_HANDLE_NULL)
		    TEE_FreeTransientObject(key);
		if (persistent_key != TEE_HANDLE_NULL)
		    TEE_CloseObject(persistent_key);
		return res;
	}
	
	// Write key to persistent storage
	res = TEE_WriteObjectData(persistent_key, key_buffer, key_size);
	
	if (key != TEE_HANDLE_NULL)
		    TEE_FreeTransientObject(key);
	if (persistent_key != TEE_HANDLE_NULL)
		    TEE_CloseObject(persistent_key);
	
	// Clear sensitive data
	TEE_MemFill(key_buffer, 0, sizeof(key_buffer));
	
	if (res != TEE_SUCCESS)
    	IMSG("Error while writing key in Trusted Storage Space: 0x%x\n", res);
        return res;	
}

static TEE_Result load_key(void) {
	DMSG("has been called");
	TEE_Result res;
	TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;
	uint8_t key_buffer[32];
	uint32_t key_size = sizeof(key_buffer);
	
	// Open persistent object (stored in Trusted Storage Space)
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
		                                    KEY_STORAGE_ID, strlen(KEY_STORAGE_ID),
		                                    TEE_DATA_FLAG_ACCESS_READ,
		                                    &persistent_key);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        IMSG("WARNING: Key does not exist in Trusted Storage Space yet");
        return TEE_SUCCESS;
	}
	
	if (res != TEE_SUCCESS) {
        IMSG("Error while opening persistent object: 0x%x\n", res);
        if (persistent_key != TEE_HANDLE_NULL)
            TEE_CloseObject(persistent_key);
        return res;
	}
	
	// Read key data
    res = TEE_ReadObjectData(persistent_key, key_buffer,sizeof(key_buffer), &key_size);
    if (res != TEE_SUCCESS) {
        IMSG("Error while reading key data: 0x%x\n", res);
        TEE_CloseObject(persistent_key);
        TEE_MemFill(key_buffer, 0, sizeof(key_buffer));
        return res;
	}
	
	/*
    * Create transient object for crypto operations
    * (based on persistent object's data)
    */
    
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, KEY_SIZE, &stored_key);
    if (res != TEE_SUCCESS) {
		IMSG("Error while allocating transient object: 0x%x\n", res);
		TEE_CloseObject(persistent_key);
		TEE_MemFill(key_buffer, 0, sizeof(key_buffer));
		return res;
	}
	
	// Initialize key attributes
    TEE_Attribute attr;
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key_buffer, key_size);
    
    /*
    * Populate transient object with key material
    * (obtained from persistent object)
    */
    
    res = TEE_PopulateTransientObject(stored_key, &attr, 1);
	
	// Clear sensitive data
	TEE_CloseObject(persistent_key);
	TEE_MemFill(key_buffer, 0, sizeof(key_buffer));
	if (res != TEE_SUCCESS)
	    IMSG("Error while populating transient object: 0x%x\n", res);
		IMSG("Key loaded in memory, ready for cryptographic operations");
		return res;   
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
 
TEE_Result TA_CreateEntryPoint(void) {
    DMSG("has been called");
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
*/
 
void TA_DestroyEntryPoint(void) {
        DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
*/
 
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,TEE_Param __maybe_unused params[4],void __maybe_unused **sess_ctx) {
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,TEE_PARAM_TYPE_NONE,TEE_PARAM_TYPE_NONE,TEE_PARAM_TYPE_NONE);
	DMSG("has been called");
		if (param_types != exp_param_types)
		    return TEE_ERROR_BAD_PARAMETERS;
	
	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	* The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Opening Session; loading key\n");
	/* Load the key when the session starts */
	return load_key();
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
*/

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx) {
	IMSG("Closing Session; clearing sensitive data\n");
	if (stored_key != TEE_HANDLE_NULL)
		    TEE_FreeTransientObject(stored_key);
}

static TEE_Result encrypt_buffer(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,TEE_PARAM_TYPE_MEMREF_OUTPUT,TEE_PARAM_TYPE_NONE,TEE_PARAM_TYPE_NONE);
    
    if (param_types != exp_param_types)
    	return TEE_ERROR_BAD_PARAMETERS;
    
    // Create operation with CTR mode
	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR,
                           TEE_MODE_ENCRYPT, KEY_SIZE);

	if (res != TEE_SUCCESS) {
    	EMSG("Error while creating cryptographic operation: 0x%x\n", res);
    	if (op != TEE_HANDLE_NULL)
            TEE_FreeOperation(op);
        return res;
	}
	
	res = TEE_SetOperationKey(op, stored_key);
	if (res != TEE_SUCCESS) {
		EMSG("Error while setting operation key: 0x%x\n", res);
		if (op != TEE_HANDLE_NULL)
		        TEE_FreeOperation(op);
		    return res;
	}

	// Generate Initialization Value
	uint8_t iv[16] = {0};
	TEE_GenerateRandom(iv, sizeof(iv));
	
	// Write IV to beginning of output buffer
	memcpy(params[1].memref.buffer, iv, sizeof(iv));
	TEE_CipherInit(op, iv, sizeof(iv));
	
	// Encrypt data
    size_t encrypted_size = params[1].memref.size - sizeof(iv);
    res = TEE_CipherDoFinal(op,
                           params[0].memref.buffer,
                           params[0].memref.size,
                           (uint8_t*)params[1].memref.buffer + sizeof(iv),
                           &encrypted_size);
	
	if (res != TEE_SUCCESS) {
        EMSG("Error in TEE_CipherDoFinal: 0x%x\n", res);
        if (op != TEE_HANDLE_NULL)
                TEE_FreeOperation(op);
            return res;
	}
	
	// Adjust total size to include IV
    params[1].memref.size = sizeof(iv) + encrypted_size;
    if (op != TEE_HANDLE_NULL)
            TEE_FreeOperation(op);
		return res;
	}

static TEE_Result decrypt_buffer(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_MEMREF_OUTPUT,TEE_PARAM_TYPE_NONE,TEE_PARAM_TYPE_NONE);  
	if (param_types != exp_param_types)
    	return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size <= 16) {
		EMSG("Input buffer too small");
		return TEE_ERROR_BAD_PARAMETERS;
	}
  	
  	// Create operation with CTR mode
	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR,
		                       TEE_MODE_DECRYPT, KEY_SIZE);
	if (res != TEE_SUCCESS){
		EMSG("Error while creating cryptographic operation: 0x%x\n", res);
		if (op != TEE_HANDLE_NULL)
	        TEE_FreeOperation(op);
	    	return res;
	}
	
	res = TEE_SetOperationKey(op, stored_key);
	if (res != TEE_SUCCESS) {
		EMSG("Error while setting operation key: 0x%x\n", res);
		if (op != TEE_HANDLE_NULL)
		        TEE_FreeOperation(op);
		    return res;
	}
	
	
    // Get IV from beginning of input buffer
    uint8_t *iv = params[0].memref.buffer;
    uint8_t *encrypted_data = (uint8_t*)params[0].memref.buffer + 16;
    size_t encrypted_size = params[0].memref.size - 16;
    TEE_CipherInit(op, iv, 16);
    
    // Decrypt data
    res = TEE_CipherDoFinal(op,
                           encrypted_data,
                           encrypted_size,
                           params[1].memref.buffer,
                           &params[1].memref.size);
    if (res != TEE_SUCCESS)
        EMSG("Error in TEE_CipherDoFinal: 0x%x\n", res);
    if (op != TEE_HANDLE_NULL)
                TEE_FreeOperation(op);
	return res;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
(void)&sess_ctx; /* Unused parameter */
        
        switch (cmd_id) {
        case TA_SMALL_APP_CMD_GENERATE_KEY:
                return generate_and_store_key();
        case TA_SMALL_APP_CMD_ENCRYPT:
                return encrypt_buffer(param_types, params);
        case TA_SMALL_APP_CMD_DECRYPT:
                return decrypt_buffer(param_types, params);
        default:
        		return TEE_ERROR_BAD_PARAMETERS;
        }
}
  	
