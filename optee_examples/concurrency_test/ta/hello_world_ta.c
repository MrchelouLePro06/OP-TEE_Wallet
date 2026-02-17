#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define CMD_INCREMENT_COMPTEUR 10

static int compteur_partage = 0;

TEE_Result TA_CreateEntryPoint(void) {
    IMSG(">>> TA CONCURRENCE : Init (Single Instance) <<<");
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    IMSG(">>> TA CONCURRENCE : Detruite <<<");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param __maybe_unused params[4],
                                    void __maybe_unused **sess_ctx) {
    (void)&param_types;
    (void)&params;
    (void)&sess_ctx;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx) {
    (void)&sess_ctx;
}

static TEE_Result inc_compteur(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // Simulation de travail bloquant pour tester la file d'attente
    TEE_Wait(500); 
    
    compteur_partage++;
    params[0].value.a = compteur_partage;

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    switch (cmd_id) {
    case CMD_INCREMENT_COMPTEUR:
        return inc_compteur(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
