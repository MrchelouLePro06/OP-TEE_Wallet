#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "manager_ta.h"

TEE_Result TA_CreateEntryPoint(void) {
    DMSG("TA_CreateEntryPoint successfully called.");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    DMSG("TA_DestroyEntryPoint successfully called.");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    (void)params; (void)param_types; (void)sess_ctx;
    IMSG("TA_OpenSessionEntryPoint: Session opened.");
    IMSG("Hello World From Manager!\n");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)sess_ctx;
    IMSG("TA_CloseSessionEntryPoint: Session closed.");
    IMSG("Goodbye From Manager!\n");
}

static TEE_Result route_to_ta(TEE_UUID *target, uint32_t cmd, uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_TASessionHandle sess = TEE_HANDLE_NULL;
    uint32_t origin;

    res = TEE_OpenTASession(target, TEE_TIMEOUT_INFINITE, 0, NULL, &sess, &origin);
    if (res != TEE_SUCCESS) return res;

    res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, cmd, pt, params, &origin);
    TEE_CloseTASession(sess);
    return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t pt, TEE_Param params[4]) {
    (void)sess_ctx;
    TEE_UUID auth_uuid = TA_TRUSTED_AUTHORITY_UUID;
    TEE_UUID storage_uuid = TA_STORAGE_DATA_UUID;

    switch (cmd_id) {
        case CMD_INIT_WALLET:
        case CMD_LOGIN_WALLET:
            return route_to_ta(&auth_uuid, cmd_id, pt, params);
        case CMD_ADD_DOCUMENT:
        case CMD_GET_DOCUMENT:
        case CMD_DELETE_DOCUMENT:
            return route_to_ta(&storage_uuid, cmd_id, pt, params);
        default: return TEE_ERROR_BAD_PARAMETERS;
    }
}