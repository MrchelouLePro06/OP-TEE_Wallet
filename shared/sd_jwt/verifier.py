#!/usr/bin/env python3
import socket
import json
import os
import time
import secrets
import traceback
from jwcrypto import jwk
from sd_jwt.verifier import SDJWTVerifier
from templates import get_random_required_claims, TEMPLATES

VERIFIER_PORT = 12343
KEY_FILE = "issuer_public_key.json"


def load_issuer_key():
    """Charge la clé publique de l'Issuer depuis le fichier JSON local."""
    if not os.path.exists(KEY_FILE):
        print(f"[-] ERREUR CRITIQUE : Le fichier '{KEY_FILE}' est introuvable dans le dossier courant !")
        exit(1)
        
    with open(KEY_FILE, "r", encoding="utf-8") as f:
        key_dict = json.load(f)
        
    print(f"[+] Clé publique de l'Issuer chargée avec succès depuis {KEY_FILE}")
    clean_dict = {k: v for k, v in key_dict.items() if k in ["kty", "crv", "x", "y"]}
    return jwk.JWK(**clean_dict)


# Instanciation de la clé au démarrage
ISSUER_PUB_KEY = load_issuer_key()


def cb_get_issuer_key(issuer, header):
    """Callback exigée par SDJWTVerifier pour valider la signature initiale du JWS."""
    return ISSUER_PUB_KEY


def start_verifier():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", VERIFIER_PORT))
    server_socket.listen(5)
    
    print(f"[*] Serveur Vérificateur à l'écoute sur le port {VERIFIER_PORT}...\n")

    while True:
        client_sock, addr = server_socket.accept()
        print(f"[+] Connexion reçue de {addr}")
        
        try:
            # 1. Envoi du Challenge d'Autorité dynamique au Wallet
            #    Génération dynamique pour chaque connexion client
            session_nonce = f"NONCE-{secrets.token_hex(12)}"
            current_iat = int(time.time())

            # Tirage aléatoire des claims réclamées pour tous les documents gérés
            dynamic_required_claims = {
                doc_name: get_random_required_claims(doc_name)
                for doc_name in TEMPLATES.keys()
            }

            challenge = {
                "nonce": session_nonce,
                "aud": "https://verifier.example.com/callback",
                "iat": current_iat,
                "required_claims": dynamic_required_claims
            }

            print(f"[*] Envoi du Challenge (Nonce: {session_nonce})")
            client_sock.sendall(json.dumps(challenge).encode('utf-8'))
            
            # 2. Réception du jeton de présentation (Verifiable Presentation - VP)
            presentation_data = client_sock.recv(16384).decode('utf-8').strip()
            print(f"[+] Présentation reçue du Wallet ({len(presentation_data)} octets)")

            # 3. Vérification complète via la bibliothèque officielle SD-JWT
            try:
                verifier_inst = SDJWTVerifier(
                    sd_jwt_presentation=presentation_data,
                    cb_get_issuer_key=cb_get_issuer_key,
                    expected_aud=challenge["aud"],
                    expected_nonce=challenge["nonce"]
                )
                
                # Récupération sécurisée des claims validées
                verified_claims = {}
                if hasattr(verifier_inst, "_sd_jwt_payload"):
                    verified_claims = verifier_inst._sd_jwt_payload
                elif hasattr(verifier_inst, "get_verified_claims"):
                    res = verifier_inst.get_verified_claims
                    verified_claims = res() if callable(res) else res

                print("\n=======================================================")
                print("🎉 VERDICT: SUCCESS ! Tout est valide !")
                print("=======================================================")
                print(f"Attributs certifiés par TrustZone : {json.dumps(verified_claims, indent=2)}\n")
                
                client_sock.sendall(b"VERDICT: SUCCESS")

            except Exception as e:
                print(f"\n[-] VERDICT: REJECT_CRYPTO_ERROR ({e})")
                print("--- TRACEBACK COMPLET DE L'ERREUR ---")
                traceback.print_exc()
                print("-------------------------------------\n")
                client_sock.sendall(f"VERDICT: REJECT_CRYPTO_ERROR ({e})".encode('utf-8'))

        except Exception as err:
            print(f"[-] Erreur réseau : {err}")
        finally:
            client_sock.close()


if __name__ == "__main__":
    start_verifier()
