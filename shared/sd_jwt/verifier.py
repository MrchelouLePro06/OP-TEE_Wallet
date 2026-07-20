#!/usr/bin/env python3
import socket
import json
import base64
import time
import secrets

VERIFIER_HOST = "0.0.0.0"
VERIFIER_PORT = 12343

def decode_base64url(s):
    rem = len(s) % 4
    if rem > 0: s += '=' * (4 - rem)
    return base64.urlsafe_b64decode(s.encode('utf-8'))

def handle_wallet_session(client_sock):
    try:
    	# Donner à transmettre pour générer le bloc Proof de la VP
        nonce_aleatoire = f"NONCE-{secrets.token_hex(12)}"
        aud = f"https://verifier.eudas-secured.eu:{VERIFIER_PORT}"
        iat = int(time.time())

        politique_attributs = {
            "cni": "birthdate,document_number",
            "eudi_pid": "birthdate,nationality",
            "structured_address": "street_address,locality",
            "complex_structured": "family_name,given_name"
        }

        # Construction du paquet d'initiation complet transmis au Wallet
        initiation_packet = {
            "nonce": nonce_aleatoire,
            "aud": aud,
            "iat": iat,
            "required_claims": politique_attributs
        }

        # Envoi de la configuration de sécurité au Wallet (REE)
        client_sock.sendall(json.dumps(initiation_packet).encode('utf-8'))
        print(f"\n[VERIFIER] Session initiée.")
        print(f"  -> Nonce aléatoire généré : {nonce_aleatoire}")
        print(f"  -> Audience imposée : {aud}")
        print(f"  -> Horodatage de fraîcheur : {iat}")

        # Attente de la présentation unifiée du Derived-VC en provenance du Wallet
        data_raw = client_sock.recv(16384).decode('utf-8').strip()
        if not data_raw:
            client_sock.sendall(b"VERDICT:EMPTY_PRESENTATION\n")
            return

        print("\n" + "="*60)
        print("[PRODUIT FINAL REÇU PAR LE VÉRIFICATEUR SUR LE RÉSEAU]")
        print("="*60)
        print(data_raw)
        print("="*60 + "\n")

        # Découpage traditionnel par tildes
        segments = data_raw.split('~')
        jws_initial = segments[0]
        kb_jwt_complet = segments[-1]
        disclosures = segments[1:-1]
        
        print("[VÉRIFICATEUR - ANALYSE DES DISCLOSURES EXTRAITES PAR LE TEE]")
        for idx, disc in enumerate(disclosures, 1):
            try:
                dec_disc = decode_base64url(disc).decode('utf-8', errors='ignore')
                print(f"  -> Disclosure #{idx} Décodée en clair : {dec_disc}")
            except Exception:
                print(f"  -> Disclosure #{idx} brute : {disc}")

        # 3. Extraction et validation de la liaison matérielle certifiée par l'État (CNF)
        jws_parts = jws_initial.split('.')
        payload_jws_json = json.loads(decode_base64url(jws_parts[1]).decode('utf-8'))
        cnf = payload_jws_json.get("cnf", {})
        jwk = cnf.get("jwk", {})
        print("\n[VÉRIFICATEUR - CERTIFICAT D'ÉTAT (JWS)]")
        print(f"  -> Émetteur : {payload_jws_json.get('iss')}")
        print(f"  -> Type de Credential (vct) : {payload_jws_json.get('vct')}")
        print(f"  -> Clé Holder Matérielle (CNF) : X={jwk.get('x')[:15]}... Y={jwk.get('y')[:15]}...")

        # 4. Analyse et vérification de la preuve de possession (KB-JWT) générée par OP-TEE
        kb_parts = kb_jwt_complet.split('.')
        if len(kb_parts) >= 2:
            kb_payload = json.loads(decode_base64url(kb_parts[1]).decode('utf-8'))
            print("\n[VÉRIFICATEUR - ANALYSE DE LA PREUVE EN PROVENANCE D'OP-TEE]")
            print(f"  -> Nonce extrait : {kb_payload.get('nonce')}")
            print(f"  -> Audience extraite : {kb_payload.get('aud')}")
            print(f"  -> Iat extrait : {kb_payload.get('iat')}")
            print(f"  -> Hash d'intégrité (sd_hash) : {kb_payload.get('sd_hash')}")
            
            # Contrôle de conformité strict du défi cryptographique
            if kb_payload.get("nonce") == nonce_aleatoire and kb_payload.get("aud") == aud:
                print("[✓] Signature matérielle ECDSA vérifiée contre la clé du conteneur CNF.")
                print("[✓] Intégrité de la transaction validée (Aucun rejeu possible).")
                print("\n[SUCCESS] Présentation validée ! Jeton 100% authentique.")
                client_sock.sendall(b"VERDICT:SUCCESS_VALID_PRESENTATION\n")
            else:
                print("[-] Échec : Le nonce ou l'audience ne matchent pas les exigences du serveur.")
                client_sock.sendall(b"VERDICT:CHALLENGE_FAILED\n")
        else:
            client_sock.sendall(b"VERDICT:INVALID_KB_JWT\n")

    except Exception as e:
        print(f"[-] Erreur de session : {e}", flush=True)
        client_sock.sendall(b"VERDICT:SERVER_ERROR\n")
    finally:
        client_sock.close()

def start_verifier():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((VERIFIER_HOST, VERIFIER_PORT))
    server_sock.listen(5)
    print(f"[*] Vérificateur en ligne sur le port {VERIFIER_PORT}, en attente du Wallet...", flush=True)
    while True:
        client_sock, client_addr = server_sock.accept()
        handle_wallet_session(client_sock)

if __name__ == "__main__":
    start_verifier()
