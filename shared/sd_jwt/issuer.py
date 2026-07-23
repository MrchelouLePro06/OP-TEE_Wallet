#!/usr/bin/env python3
import socket
import json
import os
import traceback
from jwcrypto import jwk
from sd_jwt.issuer import SDJWTIssuer
from templates import get_claims_template

ISSUER_PORT = 12344
ISSUER_PRIVATE_KEY_FILE = "issuer_private_key.json"


def load_issuer_private_key():
    """Charge la clé privée de l'Issuer depuis le fichier JSON local."""
    if not os.path.exists(ISSUER_PRIVATE_KEY_FILE):
        print(f"[-] ERREUR CRITIQUE : Le fichier '{ISSUER_PRIVATE_KEY_FILE}' est introuvable !")
        exit(1)
        
    with open(ISSUER_PRIVATE_KEY_FILE, "r", encoding="utf-8") as f:
        key_dict = json.load(f)
        
    print(f"[+] Clé privée de l'Issuer chargée depuis {ISSUER_PRIVATE_KEY_FILE}")
    return jwk.JWK(**key_dict)


ISSUER_PRIVATE_KEY = load_issuer_private_key()


def start_issuer():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", ISSUER_PORT))
    server_socket.listen(5)
    
    print(f"[*] Serveur Émetteur (Issuer) Générique à l'écoute sur le port {ISSUER_PORT}...\n")

    while True:
        client_sock, addr = server_socket.accept()
        print(f"[+] Demande d'enrôlement reçue de {addr}")
        
        try:
            raw_req = client_sock.recv(4096).decode('utf-8').strip()
            if not raw_req:
                print("[-] Requête vide reçue.")
                continue

            request_data = json.loads(raw_req)
            
            # Validation du document
            doc_name = request_data.get("doc_name")
            if not doc_name:
                print("[-] ERREUR : Aucun 'doc_name' fourni dans la requête d'enrôlement.")
                continue

            holder_jwk = request_data.get("holder_public_key")
            if not holder_jwk:
                print(f"[-] ERREUR : Aucune clé publique du Holder fournie pour '{doc_name}'.")
                continue

            print(f"[*] Génération du SD-JWT pour le modèle : '{doc_name}'")

            # Chargement du modèle de claims depuis templates.py
            try:
                user_claims = get_claims_template(doc_name, holder_jwk)
            except Exception as tmpl_err:
                print(f"[-] ERREUR : Impossible d'obtenir le modèle pour '{doc_name}': {tmpl_err}")
                continue

            # Instanciation du moteur SD-JWT IETF
            try:
                sdjwt_at_issuer = SDJWTIssuer(
                    user_claims=user_claims,
                    issuer_keys=ISSUER_PRIVATE_KEY,
                    sign_alg="ES256"
                )
            except TypeError:
                sdjwt_at_issuer = SDJWTIssuer(
                    user_claims=user_claims,
                    issuer_key=ISSUER_PRIVATE_KEY,
                    sign_alg="ES256"
                )

            # Récupération et envoi du jeton compact émis
            sd_jwt_issuance = sdjwt_at_issuer.sd_jwt_issuance

            print(f"[+] Succès ! SD-JWT généré pour '{doc_name}' ({len(sd_jwt_issuance)} octets). Envoi au Wallet...")
            client_sock.sendall(sd_jwt_issuance.encode('utf-8'))

        except Exception as e:
            print(f"\n[-] ERREUR CRITIQUE D'ÉMISSION sur '{doc_name}': {e}")
            print("--- TRACEBACK ISSUER ---")
            traceback.print_exc()
            print("------------------------\n")
        finally:
            client_sock.close()


if __name__ == "__main__":
    start_issuer()
