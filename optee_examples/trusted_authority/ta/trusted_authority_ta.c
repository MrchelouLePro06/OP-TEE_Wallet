#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <trusted_authority_ta.h>

static char stored_name[MAX_NAME_LEN];
static uint32_t stored_age;
static bool data_has_been_stored = false;

TEE_Result TA_CreateEntryPoint(void) {
    DMSG("TA_CreateEntryPoint successfully called.");
    data_has_been_stored = false;
    memset(stored_name, 0, MAX_NAME_LEN);
    stored_age = 0;
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("TA_DestroyEntryPoint successfully called.");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    (void)params; (void)param_types; (void)sess_ctx;
    IMSG("TA_OpenSessionEntryPoint: Session opened.");
    IMSG("Hello World Trusted Authority!\n");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)sess_ctx;
    IMSG("TA_CloseSessionEntryPoint: Session closed.");
    IMSG("Goodbye From Trusted Authority!\n");
}

static TEE_Result store_wallet_data(uint32_t param_types, TEE_Param params[4]) {
    const uint32_t expected_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    if (param_types != expected_param_types) return TEE_ERROR_BAD_PARAMETERS;
    
    if (params[0].memref.buffer == NULL || params[0].memref.size == 0 ||
        params[0].memref.size >= MAX_NAME_LEN) {
        EMSG("store_wallet_data: Invalid name parameter (size %u)", params[0].memref.size); 
        return TEE_ERROR_BAD_PARAMETERS;
    } 

    memset(stored_name, 0, MAX_NAME_LEN);
    TEE_MemMove(stored_name, params[0].memref.buffer, params[0].memref.size);

    stored_age = params[1].value.a;
    data_has_been_stored = true;
    
    IMSG("Stored data: Name='%s', Age=%u.", stored_name, stored_age);
    return TEE_SUCCESS;
}

static TEE_Result check_age(uint32_t param_types, TEE_Param params[4]) { 
    const uint32_t expected_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, 
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE); 
    
    char name_to_check[MAX_NAME_LEN];
    
    if (param_types != expected_param_types) return TEE_ERROR_BAD_PARAMETERS; 
    
    if (!data_has_been_stored) { 
        IMSG("check_age: No data stored yet."); 
        params[1].value.a = 0; // False 
        return TEE_SUCCESS; 
    } 
    
    if (params[0].memref.buffer == NULL || params[0].memref.size == 0 || params[0].memref.size >= MAX_NAME_LEN) { 
        EMSG("check_age: Invalid name parameter."); 
        params[1].value.a = 0; 
        return TEE_ERROR_BAD_PARAMETERS; 
    }
     
    memset(name_to_check, 0, MAX_NAME_LEN); 
    TEE_MemMove(name_to_check, params[0].memref.buffer, params[0].memref.size); 
    
    IMSG("check_age: Received: '%s'. Stored: '%s'", name_to_check, stored_name); 
    
    if (strcmp(stored_name, name_to_check) == 0) { 
        if (stored_age >= 18) { 
            params[1].value.a = 1; // True 
            IMSG("Age verification PASSED (Age: %u)", stored_age); 
        } 
        else { 
            params[1].value.a = 0; // False 
            IMSG("Age verification FAILED (Age: %u) - underage", stored_age); 
        } 
    } 
    else { 
        params[1].value.a = 0; // False (name mismatch) 
        IMSG("Name mismatch: Stored='%s', Received='%s'", stored_name, name_to_check); 
    } 
    
    return TEE_SUCCESS; 
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    (void)sess_ctx;
    DMSG("TA_InvokeCommandEntryPoint: Received command ID %u", cmd_id);
    
    switch (cmd_id) {
        case CMD_STORE_WALLET_DATA: 
            return store_wallet_data(param_types, params);
        case CMD_CHECK_AGE:
            return check_age(param_types, params);
        default:
            EMSG("Unknown command ID: %u", cmd_id); 
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
