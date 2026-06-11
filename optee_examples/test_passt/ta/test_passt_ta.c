#include <inttypes.h>
#include <test_passt_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{

}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session){
	IMSG("Hello from test_passt");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
IMSG("Goodbye from test_passt");
}

static TEE_Result confirm_reception(uint32_t pt, TEE_Param params[4]) {
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    uint32_t key_size = 2048;

    // Vérification des types de paramètres
    // [0] Message entrant (INPUT), [1] Signature sortante (OUTPUT)
    uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                      TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    
    if (pt != exp_pt) return TEE_ERROR_BAD_PARAMETERS;

    // GÉNÉRATION DE LA CLÉ ÉPHÉMÈRE
    // On alloue un conteneur pour une paire de clés RSA
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Erreur allocation objet éphémère : 0x%08x", res);
        return res;
    }

    res = TEE_GenerateKey(key_handle, key_size, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("Erreur génération clé RSA : 0x%08x", res);
        goto cleanup;
    }

    // PRÉPARATION DE L'OPÉRATION DE SIGNATURE
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_SIGN, key_size);
    if (res != TEE_SUCCESS) {
        EMSG("Erreur allocation opération : 0x%08x", res);
        goto cleanup;
    }

    // On lie la clé générée à l'opération
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Erreur liaison clé-opération : 0x%08x", res);
        goto cleanup;
    }

    // SIGNATURE DU MESSAGE
    // TEE_AsymmetricSignDigest va hacher le message (SHA256) puis le signer
    res = TEE_AsymmetricSignDigest(op_handle, NULL, 0, 
                                   params[0].memref.buffer, params[0].memref.size,
                                   params[1].memref.buffer, &params[1].memref.size);

    if (res == TEE_SUCCESS) {
        IMSG("TA: Message signé avec clé éphémère (%u octets)", params[1].memref.size);
    } else {
        EMSG("Erreur lors de la signature : 0x%08x", res);
    }

cleanup:
    // Nettoyage systématique des ressources pour éviter les fuites mémoire dans le Secure World
    if (op_handle != TEE_HANDLE_NULL) 
        TEE_FreeOperation(op_handle);
    
    if (key_handle != TEE_HANDLE_NULL) 
        TEE_FreeTransientObject(key_handle); // Supprime la clé de la RAM
        
    return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session,
				      uint32_t command,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (command) {
	case TA_TEST_PASST_CMD_CONF:
		return confirm_reception(param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
