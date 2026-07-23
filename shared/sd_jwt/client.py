#!/usr/bin/env python3
import socket
import json
import subprocess
import sys
import os
import base64
import hashlib

ISSUER_HOST = "10.212.127.253"
ISSUER_PORT = 12344
VERIFIER_HOST = "10.212.127.253"
VERIFIER_PORT = 12343

PATH_CA_BINARY = "/usr/bin/optee_example_sd_jwt"


def base64url_encode(payload_bytes):
    """Encode des octets au format Base64URL sans padding (RFC 7515)."""
    return base64.urlsafe_b64encode(payload_bytes).decode('utf-8').replace('=', '')


def der_to_raw_signature(der_bytes):
    """Convertit la structure ASN.1 DER renvoyée par OP-TEE en format brut R+S (64 octets)."""
    try:
        if der_bytes[0] != 0x30:
            return der_bytes
        idx = 2
        if der_bytes[idx] != 0x02:
            return der_bytes
        idx += 1
        r_len = der_bytes[idx]
        idx += 1
        r_bytes = der_bytes[idx:idx+r_len]
        idx += r_len
        if der_bytes[idx] != 0x02:
            return der_bytes
        idx += 1
        s_len = der_bytes[idx]
        idx += 1
        s_bytes = der_bytes[idx:idx+s_len]
        
        if len(r_bytes) > 32 and r_bytes[0] == 0x00:
            r_bytes = r_bytes[1:]
        if len(s_bytes) > 32 and s_bytes[0] == 0x00:
            s_bytes = s_bytes[1:]
            
        return r_bytes.rjust(32, b'\x00') + s_bytes.rjust(32, b'\x00')
    except Exception:
        return der_bytes


def run_enrolment(doc_name):
    print(f"\n--- [PYTHON ENROLMENT: {doc_name.upper()}] ---", flush=True)
    
    # Génération de la clé matérielle par la TA TrustZone
    res = subprocess.run([PATH_CA_BINARY, "genkey", doc_name], capture_output=True, text=True)
    
    pubkey_raw = ""
    for line in res.stdout.split("\n"):
        if line.startswith("PUBKEY_RESULT:"):
            pubkey_raw = line.split("PUBKEY_RESULT:")[1].strip()
            
    if not pubkey_raw or "|" not in pubkey_raw:
        print("[-] Erreur : Pas de clé générée par le TEE.", flush=True)
        print(f"[STDOUT TEE]: {res.stdout}\n[STDERR TEE]: {res.stderr}", flush=True)
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
    
    print(f"[*] Envoi à l'Issuer. JWK généré : {json.dumps(payload_issuer['holder_public_key'])}", flush=True)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ISSUER_HOST, ISSUER_PORT))
    sock.sendall(json.dumps(payload_issuer).encode('utf-8'))
    sd_jwt_complete = sock.recv(16384).decode('utf-8').strip()
    sock.close()

    print(f"[+] Token reçu de l'Issuer. Sauvegarde dans /tmp/{doc_name}_token.tmp", flush=True)
    temp_path = f"/tmp/{doc_name}_token.tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        f.write(sd_jwt_complete)
        f.flush()
        os.fsync(f.fileno())

    print("[*] Stockage du Token dans le TEE (RPMB)...", flush=True)
    res_store = subprocess.run([PATH_CA_BINARY, "store", temp_path, doc_name], capture_output=True, text=True)
    print(f"[TEE RESPONSE]: {res_store.stdout}", flush=True)


def run_presentation(doc_name):
    print(f"\n--- [PYTHON PRESENTATION: {doc_name.upper()}] ---", flush=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((VERIFIER_HOST, VERIFIER_PORT))
    
    # Réception du Challenge (envoyé par le verifier)
    req_json = json.loads(sock.recv(4096).decode('utf-8').strip())
    nonce = req_json.get("nonce")
    aud = req_json.get("aud")
    iat = req_json.get("iat")
    
    # Extraction Dynamique Stricte
    req_claims = req_json.get("required_claims", {})
    if doc_name not in req_claims:
        print(f"[-] ERREUR : Le vérificateur ne réclame pas le document '{doc_name}'. Documents demandés: {list(req_claims.keys())}")
        sock.close()
        return

    paths_arg = req_claims[doc_name]
    print(f"[+] Challenge Reçu - Nonce: {nonce}, Aud: {aud}, Iat: {iat}")
    print(f"[+] Claims extraites pour '{doc_name}': {paths_arg}")
    
    consigne_doc = f"{doc_name}|{paths_arg}"

    # passage 1: Demander la DVC_STRUCTURE filtrée par le TEE
    kb_header = {"alg": "ES256", "typ": "kb+jwt"}
    dummy_payload = {"nonce": nonce, "aud": aud, "iat": iat, "sd_hash": "PENDING_TEE"}
    
    kb_header_b64 = base64url_encode(json.dumps(kb_header, separators=(',', ':')).encode('utf-8'))
    dummy_payload_b64 = base64url_encode(json.dumps(dummy_payload, separators=(',', ':')).encode('utf-8'))
    dummy_jwt_block = f"{kb_header_b64}.{dummy_payload_b64}"

    print("[*] Passage 1 : Extraction de la DVC_STRUCTURE depuis le TEE...", flush=True)
    res1 = subprocess.run([PATH_CA_BINARY, "presentation", consigne_doc, dummy_jwt_block], capture_output=True, text=True)
    
    dvc_structure = ""
    for line in res1.stdout.split("\n"):
        if "DVC_STRUCTURE:" in line:
            dvc_structure = line.split("DVC_STRUCTURE:")[1].strip()

    if not dvc_structure:
        print("[-] Erreur : Impossible d'extraire DVC_STRUCTURE du TEE.", flush=True)
        print(f"[STDOUT]: {res1.stdout}\n[STDERR]: {res1.stderr}", flush=True)
        sock.close()
        return

    # CALCUL DU SD_HASH SUR LA DVC_STRUCTURE D'OP-TEE
    sha256_brut = hashlib.sha256(dvc_structure.encode('utf-8')).digest()
    sd_hash = base64url_encode(sha256_brut)
    print(f"[+] SD_HASH réglementaire calculé : {sd_hash}", flush=True)

    # passage 2: Construction du bloc KB et Signature matérielle TrustZone
    kb_payload = {"nonce": nonce, "aud": aud, "iat": iat, "sd_hash": sd_hash}
    kb_payload_b64 = base64url_encode(json.dumps(kb_payload, separators=(',', ':')).encode('utf-8'))
    unsigned_jwt_block = f"{kb_header_b64}.{kb_payload_b64}"

    print("[*] Passage 2 : Signature matérielle par le TEE...", flush=True)
    res2 = subprocess.run([PATH_CA_BINARY, "presentation", consigne_doc, unsigned_jwt_block], capture_output=True, text=True)

    signature_hex = ""
    for line in res2.stdout.split("\n"):
        if "SIGNATURE:" in line:
            signature_hex = line.split("SIGNATURE:")[1].strip()

    if not signature_hex:
        print("[-] Erreur critique : Impossible de capturer la signature du TEE.", flush=True)
        print(f"[STDOUT]: {res2.stdout}\n[STDERR]: {res2.stderr}", flush=True)
        sock.close()
        return

    # Conversion de la signature matérielle et assemblage final du VP
    raw_sig_bytes = der_to_raw_signature(bytes.fromhex(signature_hex))
    kb_signature_b64 = base64url_encode(raw_sig_bytes)

    presentation_finale = f"{dvc_structure}{kb_header_b64}.{kb_payload_b64}.{kb_signature_b64}"
    print(f"[+] Jeton de Présentation final envoyé au vérificateur ({len(presentation_finale)} octets) :\n{presentation_finale}\n", flush=True)
    
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
