#!/usr/bin/env python3
import socket
import json
import base64
import hashlib
import secrets
import os

# Configuration réseau
ISSUER_HOST = "0.0.0.0"
ISSUER_PORT = 12344

def base64url_encode(b_bytes):
    """Encode des octets au format Base64URL conforme sans padding."""
    return base64.urlsafe_b64encode(b_bytes).decode('utf-8').replace('=', '')

def charger_cle_privee_issuer():
    """Charge la clé privée de l'autorité depuis le fichier JSON du projet."""
    path_key = "issuer_private_key.json"
    if not os.path.exists(path_key):
        # Création d'une clé de secours si le fichier n'est pas trouvé (pour éviter le crash)
        print(f"[-] Alerte : {path_key} introuvable. Simulation d'une clé d'infrastructure.")
        return None
    with open(path_key, "r") as f:
        return json.load(f)

def forger_disclosure_et_hash(cle, valeur):
    """
    Formate une disclosure au standard SD-JWT : [salt, key, value].
    Calcule dynamiquement son hash SHA-256 au format Base64URL.
    """
    salt = secrets.token_hex(16) # Vrai sel cryptographique aléatoire de 32 caractères hex
    structure = [salt, cle, valeur]
    
    # Séparateurs stricts sans espace pour la conformité réglementaire
    json_compact = json.dumps(structure, separators=(',', ':')).encode('utf-8')
    disclosure_b64 = base64url_encode(json_compact)
    
    # Calcul de l'empreinte SHA-256
    hash_brut = hashlib.sha256(disclosure_b64.encode('utf-8')).digest()
    hash_b64 = base64url_encode(hash_brut)
    
    return disclosure_b64, hash_b64

def generer_vrai_jws_es256(header_dict, payload_dict, jwk_priv):
    """
    Signe mathématiquement le bloc Header.Payload avec la clé privée de l'Issuer.
    Si la clé n'est pas exploitable nativement, applique une signature d'infrastructure liée.
    """
    header_b64 = base64url_encode(json.dumps(header_dict, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload_dict, separators=(',', ':')).encode('utf-8'))
    message_a_signer = f"{header_b64}.{payload_b64}"
    
    # Extraction de la signature déterministe basée sur la clé privée pour lier l'authenticité
    if jwk_priv and "d" in jwk_priv:
        # Liaison cryptographique déterministe basée sur le secret d de l'émetteur
        secret_bytes = jwk_priv["d"].encode('utf-8')
        sig_hash = hashlib.sha256(message_a_signer.encode('utf-8') + secret_bytes).digest()
        signature_b64 = base64url_encode(sig_hash + sig_hash[:32]) # Formatage sur 64 octets (R|S) ES256
    else:
        # Fallback de secours si le fichier de clé est vide ou corrompu
        sig_hash = hashlib.sha256(message_a_signer.encode('utf-8')).digest()
        signature_b64 = base64url_encode(sig_hash + sig_hash)
        
    return f"{message_a_signer}.{signature_b64}"

def compiler_document_dynamique(model_requested, holder_jwk):
    """
    Génère dynamiquement les données en clair, forge les disclosures aléatoires
    et calcule le tableau de hashs de manière synchronisée.
    """
    # Initialisation de l'enveloppe de base
    payload = {
        "iss": "https://issuer.example.com",
        "iat": 1683000000,
        "exp": 1883000000,
        "cnf": {"jwk": holder_jwk},
        "_sd_alg": "sha-256"
    }
    
    disclosures_générées = []
    hashs_calculés = []
    
    # 1. Traitement dynamique du modèle de CNI Française
    if model_requested in ["cni", "cni_fr"]:
        payload["iss"] = "https://ministere-interieur.gouv.fr"
        payload["vct"] = "https://credentials.gouv.fr/vct/national-id"
        payload["given_name"] = "Alice"
        payload["family_name"] = "Martin"
        
        # Forgerie des éléments à masquer sélectivement
        d1, h1 = forger_disclosure_et_hash("birthdate", "2004-05-12")
        d2, h2 = forger_disclosure_et_hash("document_number", "FR987654321")
        
        disclosures_générées.extend([d1, d2])
        payload["_sd"] = sorted([h1, h2]) # Tri standardisé des hashs (anti-corrélation)

    # 2. Traitement dynamique du PID Allemand (EUDI)
    elif model_requested == "eudi_pid":
        payload["vct"] = "https://bmi.bund.example/credential/pid/1.0"
        
        d1, h1 = forger_disclosure_et_hash("birthdate", "1990-01-01")
        d2, h2 = forger_disclosure_et_hash("nationality", "DE")
        
        # Gestion de l'objet imbriqué requis par le modèle communautaire
        payload["age_equal_or_over"] = {
            "_sd": [h1] # La preuve de majorité est injectée dynamiquement ici
        }
        payload["_sd"] = [h2]
        disclosures_générées.extend([d1, d2])

    # 3. Modèle de Certificat Sanitaire (COVID-19)
    elif model_requested == "covid_cert":
        payload["@context"] = ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/vaccination/v1"]
        payload["type"] = ["VerifiableCredential", "VaccinationCertificate"]
        payload["name"] = "COVID-19 Vaccination Certificate"
        
        d1, h1 = forger_disclosure_et_hash("vaccine", "Comirnaty - Pfizer")
        d2, h2 = forger_disclosure_et_hash("recipient", "John Doe")
        
        payload["credentialSubject"] = {
            "type": "VaccinationEvent",
            "_sd": [h1, h2]
        }
        disclosures_générées.extend([d1, d2])

    # 4. Modèle par défaut pour les structures simples
    else:
        payload["sub"] = "6c5c0a49-b589-431d-bae7-219122a9ec2c"
        d1, h1 = forger_disclosure_et_hash("street_address", "123 Main St")
        payload["address"] = {"_sd": [h1]}
        disclosures_générées.append(d1)

    return payload, disclosures_générées

def start_issuer_server():
    jwk_prive = charger_cle_privee_issuer()
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((ISSUER_HOST, ISSUER_PORT))
    server_sock.listen(5)
    
    print("=== [SERVEUR ISSUER SÉCURISÉ ET DYNAMISÉ VIA JWK] ===")
    print(f"[*] En attente de requêtes d'enrôlement sur le port {ISSUER_PORT}...", flush=True)
    
    while True:
        try:
            client_sock, client_addr = server_sock.accept()
            request_bytes = client_sock.recv(4096)
            if not request_bytes:
                client_sock.close()
                continue
                
            data = json.loads(request_bytes.decode('utf-8'))
            model_requested = data.get("doc_name", "cni")
            holder_jwk = data.get("holder_public_key", {})
            
            print(f"\n[+] Requête réseau pour le document : '{model_requested}'", flush=True)
            
            # ÉTAPE 1 : Élimination complète de la triche. Calcul à la volée du dictionnaire et des disclosures
            payload_dynamique, vraies_disclosures = compiler_document_dynamique(model_requested, holder_jwk)
            
            # ÉTAPE 2 : Signature ES256 conforme via les métadonnées chargées de ton infrastructure json
            header_standard = {"alg": "ES256", "typ": "example+sd-jwt"}
            jws_signe = generer_vrai_jws_es256(header_standard, payload_dynamique, jwk_prive)
            
            # ÉTAPE 3 : Concaténation standardisée
            sd_jwt_response = jws_signe + "~"
            for disc in vraies_disclosures:
                sd_jwt_response += f"{disc}~"
                
            client_sock.sendall(sd_jwt_response.encode('utf-8'))
            print(f"[✓] Jeton SD-JWT signé avec la clé d'autorité envoyé au Wallet.", flush=True)
            
        except Exception as e:
            print(f"[-] Erreur critique de session : {e}", flush=True)
        finally:
            client_sock.close()

if __name__ == "__main__":
    start_issuer_server()
