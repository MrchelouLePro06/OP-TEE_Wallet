#!/usr/bin/env python3
"""
Agent de liaison REE (QEMU).
Pilote les appels vers les TA NIZKP et IZKP, recupère et transmet les preuves au serveur hôte.
"""

import socket
import subprocess
import sys

VERIFIER_HOST = "10.212.127.253"  # IP de la route
VERIFIER_PORT = 12344              # Port du serveur

PATH_NIZKP = "/usr/bin/optee_example_schnorrzkp"
PATH_IZKP = "/usr/bin/optee_example_schnorrizkp"

def print_usage():
    print("Usage:")
    print("  python3 ree_client.py nizkp [classic|and|or] [message]")
    print("  python3 ree_client.py izkp [message]")

def execute_nizkp(sock, sub_mode, msg):
    print(f"[REE -> TEE] Appel de la TA NIZKP : Mode = '{sub_mode}', Message = '{msg}'...")
    
    # Exécution du binaire C avec le sous-mode et le message en arguments
    res = subprocess.run([PATH_NIZKP, sub_mode, msg], capture_output=True, text=True)
    
    if res.returncode != 0 or not res.stdout.strip():
        print("[-] Erreur critique lors de l'exécution du binaire NIZKP")
        print(f"    [Code retour] : {res.returncode}")
        print(f"    [stderr]      : {res.stderr.strip()}")
        return
        
    print("[TEE] Exécution de la TA : calcul cryptographique achevé.")
    packet = res.stdout.strip()
    print("[REE] Réception du paquet brut du TEE ...")
    
    parts = packet.split(":")
    header = parts[0]
    
    # Validation adaptative selon le format produit par le main.c du REE
    if header == "NIZKP_PROOF_CLASSIC" and len(parts) != 6:
        print(f"[-] Erreur : Format classique non conforme (Reçu {len(parts)}/6).")
        return
    elif header in ["NIZKP_PROOF_MULTI_AND", "NIZKP_PROOF_MULTI_OR"] and len(parts) != 6:
        print(f"[-] Erreur : Format multi-attribut non conforme (Reçu {len(parts)}/6).")
        return
    elif header not in ["NIZKP_PROOF_CLASSIC", "NIZKP_PROOF_MULTI_AND", "NIZKP_PROOF_MULTI_OR"]:
        print(f"[-] En-tête inconnu rejeté par le protocole : {header}")
        return

    print(f"[REE -> Serveur] Envoi du paquet réseau ...")
    sock.sendall((packet + "\n").encode())
    
    verdict = sock.recv(1024).decode().strip()
    print(f"[Serveur -> REE] Réponse du serveur : {verdict}")
    print("[*] Fin de session ...")

def execute_izkp(sock, msg):
    print(f"[REE -> TEE] Appel de la TA IZKP asynchrone : Message = '{msg}'...")
    
    proc = subprocess.Popen(
        [PATH_IZKP, msg],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    print("[TEE] Exécution de la TA : calcul cryptographique ... préparation du couple (u,clé publique X)")
    print("[TEE -> REE] Envoi du paquet vers le REE")
    
    packet_init = proc.stdout.readline().strip()
    print("[REE] Réception du paquet IZKP ...")
    if not packet_init or "IZKP_INIT" not in packet_init:
        print("[-] Erreur : Impossible de récupérer le paquet d'initialisation de la TA.")
        print(f"    [stderr du C] : '{proc.stderr.read().strip()}'")
        proc.kill()
        return

    print(f"[REE -> Serveur] Envoi de l'init réseau : {packet_init}")
    sock.sendall((packet_init + "\n").encode())

    # ÉTAPES INTERACTIVES CONSERVÉES À 100%
    reply = sock.recv(1024).decode().strip()
    print(f"[Serveur -> REE] Réception du défi c (paquet {reply}) ...")
    
    if not reply.startswith("IZKP_CHALLENGE:"):
        print(f"[-] Réponse inattendue du serveur : {reply}")
        proc.kill()
        return
    
    c_hex = reply.split(":")[1].strip()
    print(f"[REE] Préparation de c pour envoi vers la TA : {c_hex}")
    print("[REE -> TEE] Envoi du défi c à la TA active...")
    
    proc.stdin.write(c_hex + "\n")
    proc.stdin.flush()

    print("[TEE] Calcul de z")
    print("[TEE -> REE] Envoi du paquet vers le REE")
    packet_z = proc.stdout.readline().strip()
    print(f"[REE] Réception de z (paquet {packet_z})")
    if not packet_z or "IZKP_RESPONSE" not in packet_z:
        print("[-] Erreur : La TA a refusé de répondre ou a fermé la session.")
        print(f"    [stderr du C] : '{proc.stderr.read().strip()}'")
        proc.kill()
        return

    print(f"[REE -> Serveur] Envoi de la réponse réseau : {packet_z}")
    sock.sendall((packet_z + "\n").encode())
    
    print("Attente d'une réponse du serveur")
    verdict = sock.recv(1024).decode().strip()
    print(f"[Serveur -> REE] Verdict final du serveur : {verdict}")
    print("[*] Fin de session ...")
    proc.wait()

def main():
    if len(sys.argv) < 2:
        print_usage()
        return

    mode = sys.argv[1]

    if mode == "nizkp":
        # Correction du bug d'argument seul "nizkp"
        if len(sys.argv) < 3:
            print_usage()
            return
            
        sub_mode = sys.argv[2]
        if sub_mode not in ["classic", "and", "or"]:
            print_usage()
            return
            
        msg = sys.argv[3] if len(sys.argv) == 4 else "Mon message secret OP-TEE"
        
    elif mode == "izkp":
        sub_mode = None
        msg = sys.argv[2] if len(sys.argv) == 3 else "Mon message secret OP-TEE"
        
    else:
        print_usage()
        return

    print(f"[*] Connexion au Serveur ({VERIFIER_HOST}:{VERIFIER_PORT})...")
    print("[*] Début de session ...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.connect((VERIFIER_HOST, VERIFIER_PORT))
        if mode == "nizkp":
            execute_nizkp(sock, sub_mode, msg)
        else:
            execute_izkp(sock, msg)
            
    except Exception as e:
        print(f"[-] Erreur de communication réseau : {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()