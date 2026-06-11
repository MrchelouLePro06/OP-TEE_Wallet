#ifndef TA_TRUSTED_AUTHORITY_H
#define TA_TRUSTED_AUTHORITY_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_TRUSTED_AUTHORITY_UUID \
	{ 0x39382223, 0x4d1d, 0x43f8, \
		{ 0xbc, 0x1f, 0x11, 0x9a, 0x21, 0x94, 0x81, 0x05} } //39382223-4d1d-43f8-bc1f-119a21948105

/* The function IDs implemented in this TA */
#define CMD_INIT_WALLET          10 // Création initiale (Setup)
#define CMD_LOGIN_WALLET         11 // Authentification + Signature Challenge
#define CMD_ADD_DOCUMENT         12 // Ajouter un doc (ID, Diplôme...)
#define CMD_LOGOUT_WALLET        13 // Fermer la session sécurisée

#define MAX_DOC_LEN 512
#define MAX_NAME_LEN		64
#define SALT_SIZE			16
#define SHA256_HASH_SIZE	32

#define WALLET_DATA_OBJ_ID "wallet_core_data"
#define WALLET_KEY_OBJ_ID  "wallet_rsa_key"

typedef struct {
    /* Identité de base */
    char firstname[MAX_NAME_LEN];
    char lastname[MAX_NAME_LEN];
    char birth_date[16];      // Format YYYY-MM-DD
    char email[MAX_NAME_LEN];
    
    /* Sécurité */
    uint8_t password_hash[SHA256_HASH_SIZE];
    uint8_t salt[SALT_SIZE];
    
    /* Documents (PID / EUDI) */
    char id_card_number[32];
    char nationality[32];
    bool is_student;
    
    bool is_initialized;
} wallet_core_t;

#endif /*TA_HELLO_WORLD_H*/
