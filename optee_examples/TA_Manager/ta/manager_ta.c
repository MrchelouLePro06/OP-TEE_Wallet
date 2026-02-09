#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "manager_ta.h" // On inclut les IDs de l'autre TA

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World From Manager!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	IMSG("Goodbye From Manager!\n");
}

//Fonction interne pour appeler Hello World
static TEE_Result call_hello_world_inc(uint32_t *val)
{
    TEE_Result res;
    TEE_TASessionHandle session = TEE_HANDLE_NULL;
    TEE_UUID hello_uuid = TA_HELLO_WORLD_UUID;
    uint32_t ret_orig;
    TEE_Param params[4];

    //Configuration des paramètres pour correspondre à Hello World
    //Hello World attend un type VALUE_INOUT en params[0]
    uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
                                          TEE_PARAM_TYPE_NONE,
                                          TEE_PARAM_TYPE_NONE,
                                          TEE_PARAM_TYPE_NONE);

    params[0].value.a = *val;

    //On ouvre une session interne vers la TA Hello World
    res = TEE_OpenTASession(&hello_uuid,
                            TEE_TIMEOUT_INFINITE,
                            0, NULL, //Pas de paramètres de connexion
                            &session,
                            &ret_orig);
    if (res != TEE_SUCCESS) return res;

    res = TEE_InvokeTACommand(session,
                              TEE_TIMEOUT_INFINITE,
                              TA_HELLO_WORLD_CMD_INC_VALUE,
                              param_types,
                              params,
                              &ret_orig);

    //Ici on récupère la valeur modifié par la TA Hello World
    if (res == TEE_SUCCESS) {
        *val = params[0].value.a;
    }

    TEE_CloseTASession(session);

    return res;
}

static TEE_Result Call_Key_Gen(uint32_t param_types, TEE_Param params[4]){
	TEE_Result res;
    TEE_TASessionHandle session = TEE_HANDLE_NULL;
    TEE_UUID KeyGen_uuid = TA_KEY_GEN_UUID;
    uint32_t ret_orig;
    
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                           TEE_PARAM_TYPE_MEMREF_OUTPUT,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);
                           
	if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_OpenTASession(&KeyGen_uuid,
                            TEE_TIMEOUT_INFINITE,
                            0, NULL, 
                            &session,
                            &ret_orig);
    if (res != TEE_SUCCESS) return res;
    IMSG("VERIFICATION KEYGEN");
    res = TEE_InvokeTACommand(session,
                              TEE_TIMEOUT_INFINITE,
                              CMD_GENERATE_KEY,
                              param_types,
                              params,
                              &ret_orig);
                              
	TEE_CloseTASession(session);
	return res;
}

static TEE_Result Call_Verify_Age(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_TASessionHandle session = TEE_HANDLE_NULL;
    TEE_UUID auth_uuid = TA_TRUSTED_AUTHORITY_UUID;
    uint32_t ret_orig;

    res = TEE_OpenTASession(&auth_uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &session, &ret_orig);
    if (res != TEE_SUCCESS) return res;
	IMSG("VERIFICATION AGE");
    res = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE, 
                              CMD_CHECK_AGE,
                              param_types, params, &ret_orig);

    TEE_CloseTASession(session);
    return res;
}

//Point d'entrée principal du MAnager
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t pt, TEE_Param params[4])
{
    (void)&sess_ctx;

    switch (cmd_id) {
        case TA_MANAGER_CMD_TEST_HELLO:
            return call_hello_world_inc(&params[0].value.a);
        case TA_MANAGER_CMD_KEY_GEN:
        	return Call_Key_Gen(pt, params);
        case TA_MANAGER_CMD_VERIFY_AGE:
        	return Call_Verify_Age(pt,params);
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
