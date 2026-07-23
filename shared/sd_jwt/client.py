#!/usr/bin/env python3
import socket
import json
import subprocess
import sys
import os
import base64

ISSUER_HOST = "10.212.127.253"
ISSUER_PORT = 12344
VERIFIER_HOST = "10.212.127.253"
VERIFIER_PORT = 12343

PATH_CA_BINARY = "/usr/bin/optee_example_sd_jwt"


def base64url_encode(payload_bytes):
    return base64.urlsafe_b64encode(payload_bytes).decode('utf-8').replace('=', '')


def run_enrolment(doc_name):
    print(f"\n--- [PYTHON ENROLMENT: {doc_name.upper()}] ---", flush=True)
    
    res = subprocess.run([PATH_CA_BINARY, "genkey", doc_name], capture_output=True, text=True)
    
    pubkey_raw = ""
    for line in res.stdout.split("\n"):
        if line.startswith("PUBKEY_RESULT:"):
            pubkey_raw = line.split("PUBKEY_RESULT:")[1].strip()
            
    if not pubkey_raw or "|" not in pubkey_raw:
        print("[-] Erreur : Pas de clé générée par le TEE.", flush=True)
        return

    x_hex, y_hex = pubkey_raw.split("|")
    x_b64url = base64url_encode(bytes.fromhex(x_hex.strip()))
    y_b64url = base64url_encode(bytes.fromhex(y_hex.strip()))

    payload_issuer = {
        "doc_name": doc_name,
        "holder_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64url,
            "y": y_b64url
        }
    }
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ISSUER_HOST, ISSUER_PORT))
    sock.sendall(json.dumps(payload_issuer).encode('utf-8'))
    sd_jwt_complete = sock.recv(16384).decode('utf-8').strip()
    sock.close()

    temp_path = f"/tmp/{doc_name}_token.tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        f.write(sd_jwt_complete)
        f.flush()
        os.fsync(f.fileno())

    res_store = subprocess.run([PATH_CA_BINARY, "store", temp_path, doc_name], capture_output=True, text=True)
    print(f"[TEE RESPONSE]: {res_store.stdout}", flush=True)


def run_presentation(doc_name):
    print(f"\n--- [PYTHON PRESENTATION: {doc_name.upper()}] ---", flush=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((VERIFIER_HOST, VERIFIER_PORT))
    
    req_json = json.loads(sock.recv(4096).decode('utf-8').strip())
    nonce = req_json.get("nonce")
    aud = req_json.get("aud")
    iat = str(req_json.get("iat"))
    
    req_claims = req_json.get("required_claims", {})
    if doc_name not in req_claims:
        print(f"[-] ERREUR : Le vérificateur ne réclame pas le document '{doc_name}'.")
        sock.close()
        return

    paths_arg = req_claims[doc_name]
    consigne_doc = f"{doc_name}|{paths_arg}"
    challenge_arg = f"{nonce}|{aud}|{iat}"

    # PASSAGE UNIQUE DANS LA TRUSTZONE
    print("[*] Génération et Signature de la VP complète dans le Secure World...", flush=True)
    res = subprocess.run([PATH_CA_BINARY, "presentation", consigne_doc, challenge_arg], capture_output=True, text=True)

    presentation_finale = ""
    for line in res.stdout.split("\n"):
        if "VP_RESULT:" in line:
            presentation_finale = line.split("VP_RESULT:")[1].strip()

    if not presentation_finale:
        print("[-] Erreur : Pas de VP générée par le TEE.", flush=True)
        print(f"[STDOUT]: {res.stdout}\n[STDERR]: {res.stderr}", flush=True)
        sock.close()
        return

    print(f"[+] VP finale générée par la TrustZone et reçue intacte ({len(presentation_finale)} octets) :\n{presentation_finale}\n", flush=True)
    
    # Envoi direct sans aucune altération
    sock.sendall(presentation_finale.encode('utf-8'))
    print(f"[RESULTAT SERVEUR] : {sock.recv(1024).decode('utf-8').strip()}", flush=True)
    sock.close()


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        if sys.argv[1] == "enroll":
            run_enrolment(sys.argv[2])
        elif sys.argv[1] == "present":
            run_presentation(sys.argv[2])
    else:
        print("Usage: python3 client.py [enroll|present] [doc_name]")
