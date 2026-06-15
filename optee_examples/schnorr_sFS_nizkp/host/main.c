#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* API client GlobalPlatform officielle pour l'Hôte REE */
#include <tee_client_api.h>

/* En-tête de ta TA contenant l'UUID et les IDs de commandes */
#include <schnorrzkp_ta.h>

#define MODE_AND  1
#define MODE_OR   2

int main(int argc, char *argv[])
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_SCHNORR_ZKP_UUID;
    uint32_t err_origin;
    
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [classic|and|or] [message]\n", argv[0]);
        return 1;
    }

    char *mode_str = argv[1];
    char *msg = argv[2];
    uint32_t mode = 0;

    // Initialisation du contexte TEE
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed 0x%x", res);
    }

    // Ouverture de la session avec la TA
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_Opensession failed 0x%x origin 0x%x", res, err_origin);
    }

    TEEC_Operation op;
    memset(&op, 0, sizeof(op));

    // =====================================================================
    // CAS 1 : MODE CLASSIQUE (MONO-ATTRIBUT)
    // =====================================================================
    if (strcmp(mode_str, "classic") == 0) {
        uint8_t out_combined[128];
        uint8_t out_z[32];
        uint8_t out_c[32];

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT);

        op.params[0].tmpref.buffer = msg;
        op.params[0].tmpref.size = strlen(msg);
        op.params[1].tmpref.buffer = out_combined;
        op.params[1].tmpref.size = sizeof(out_combined);
        op.params[2].tmpref.buffer = out_z;
        op.params[2].tmpref.size = sizeof(out_z);
        op.params[3].tmpref.buffer = out_c;
        op.params[3].tmpref.size = sizeof(out_c);

        res = TEEC_InvokeCommand(&sess, TA_SCHNORR_ZKP_CMD, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            errx(1, "TEEC_InvokeCommand (classic) failed 0x%x", res);
        }

        char combined_hex[257];
        char z_hex[65];
        char c_hex[65];
        
        for(int i = 0; i < 128; i++) {
            sprintf(&combined_hex[i * 2], "%02X", out_combined[i]);
        }
        for(int i = 0; i < 32; i++) {
            sprintf(&z_hex[i * 2], "%02X", out_z[i]);
        }
        for(int i = 0; i < 32; i++) {
            sprintf(&c_hex[i * 2], "%02X", out_c[i]);
        }

        printf("NIZKP_PROOF_CLASSIC:%s:%s:%s:%s\n", msg, combined_hex, z_hex, c_hex);
    }
    // =====================================================================
    // CAS 2 : MODES MULTI-ATTRIBUTS (AND / OR) -> PLIAGE DU REE AU TEE
    // =====================================================================
    else if (strcmp(mode_str, "and") == 0 || strcmp(mode_str, "or") == 0) {
        mode = (strcmp(mode_str, "and") == 0) ? MODE_AND : MODE_OR;

        size_t in_size = sizeof(uint32_t) + strlen(msg);
        uint8_t *in_buffer = malloc(in_size);
        if (!in_buffer) {
            errx(1, "Malloc failed");
        }

        memcpy(in_buffer, &mode, sizeof(uint32_t));
        memcpy(in_buffer + sizeof(uint32_t), msg, strlen(msg));

        // Buffers de réception alignés sur les tailles de ta TA
        uint8_t buffer_keys[128]; 
        uint8_t buffer_u[128];    
        uint8_t buffer_zc[64];    // z1(32) + z2(32) ou c1(32) + c2(32) selon GlobalPlatform

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT);

        op.params[0].tmpref.buffer = in_buffer;
        op.params[0].tmpref.size = in_size;
        
        op.params[1].tmpref.buffer = buffer_keys;
        op.params[1].tmpref.size = sizeof(buffer_keys);
        
        op.params[2].tmpref.buffer = buffer_u;
        op.params[2].tmpref.size = sizeof(buffer_u);
        
        // pParams[3] reçoit out_c de ta TA (64 octets = c1 + c2)
        op.params[3].tmpref.buffer = buffer_zc;
        op.params[3].tmpref.size = sizeof(buffer_zc);

        res = TEEC_InvokeCommand(&sess, TA_SCHNORR_ZKP_MULTI_ATTRIBUTE_CMD, &op, &err_origin);
        free(in_buffer);
        if (res != TEEC_SUCCESS) {
            errx(1, "TEEC_InvokeCommand (multi) failed 0x%x", res);
        }

        // --- RECONSTRUCTION DU FORMAT EXIGÉ PAR TON REE_CLIENT.PY ---
        char x_hex[257]; // Fusion des clés (128 octets = 256 chars hex)
        char u_hex[257]; // Fusion des commitments (128 octets = 256 chars hex)
        char z_hex[129]; // Réponses scalaires (64 octets = 128 chars hex)
        char c_hex[129]; // Défis scalaires (64 octets = 128 chars hex)

        // Conversion Hexadécimale
        for(int i = 0; i < 128; i++) {
            sprintf(&x_hex[i * 2], "%02X", buffer_keys[i]);
        }
        for(int i = 0; i < 128; i++) {
            sprintf(&u_hex[i * 2], "%02X", buffer_u[i]);
        }
        
        // Extraction des buffers de scalaires de la TA
        // Note : op.params[2].tmpref.buffer (out_z de la TA) contient z1 et z2 (64 octets)
        for(int i = 0; i < 64; i++) {
            sprintf(&z_hex[i * 2], "%02X", buffer_u[i]); // Récupère le out_z mappé sur op.params[2]
        }
        for(int i = 0; i < 64; i++) {
            sprintf(&c_hex[i * 2], "%02X", buffer_zc[i]); // Récupère le out_c mappé sur op.params[3]
        }

        // Affichage de l'en-tête STRICTEMENT attendu par la regex de ton ree_client.py
        printf("NIZKP_PROOF_MULTI_%s:%s:%s:%s:%s:%s\n", 
               (mode == MODE_AND) ? "AND" : "OR", msg, x_hex, u_hex, z_hex, c_hex);
    } 
    else {
        fprintf(stderr, "[-] Mode inconnu. Choix possibles : classic, and, or\n");
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}