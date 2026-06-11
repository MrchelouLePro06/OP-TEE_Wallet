#!/usr/bin/env python3
"""
Vérificateur réseau interactif Schnorr (IZKP) inspiré du script de Burkhard.
Ce script se connecte à QEMU, génère le défi, et valide la preuve géométrique.

Prérequis : pip install ecdsa
"""

import socket
import os
from ecdsa import NIST256p
from ecdsa.ellipticcurve import Point

# Configuration de la courbe globale : NIST P-256 (secp256r1)
curve = NIST256p
gen = curve.generator
p = curve.order  # Ordre n de la courbe

# =====================================================================
# CONFIGURATION CRYPTO : CLÉ PUBLIQUE STATIQUE DE LA TA OP-TEE
# =====================================================================
# Coordonnées X et Y de la clé publique d'identité fixe (générée sous OpenSSL)
pub_x_static = int("69A33D89176251967BA90AE6F380DB067ACEE2A7CFDAE8BD8467A174BF8F972D", 16)
pub_y_static = int("B3CA27F7EE89E4E68D7E4FA86908E14427CF581F64C59456D09D835D655B0D68", 16)
X_identity = Point(curve.curve, pub_x_static, pub_y_static)

# Configuration Réseau IP/Port de QEMU (Remplacer 127.0.0.1 par l'IP de QEMU si pont réseau)
QEMU_HOST = "10.212.109.9"
QEMU_PORT = 12345

def Verify_IZKP_Burkhard(X, u, c, z):
    """
    Équation de vérification géométrique de Schnorr (Format Burkhard)
    Vérifie si : z * G == u + c * X
    Ce qui équivaut à isoler u : u' = (z * G) + ((-c mod p) * X)
    """
    u_prime = (gen * z) + (X * (-c % p))
    return u_prime == u

def run_verifier():
    print("==================================================")
    print("  VÉRIFICATEUR INTERACTIF SCHNORR (MODE RÉSEAU)   ")
    print("==================================================")

    print(f"[*] Connexion au serveur de l'enclave QEMU ({QEMU_HOST}:{QEMU_PORT})...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect((QEMU_HOST, QEMU_PORT))
        print("[+] Connexion établie.")

        # -----------------------------------------------------------------
        # ÉTAPE 1 : Demander l'engagement géométrique 'u'
        # -----------------------------------------------------------------
        print("[->] Envoi : REQ_COMMITMENT")
        sock.sendall(b"REQ_COMMITMENT\n")

        reply = sock.recv(2048).decode().strip()
        if not reply.startswith("RESP_COMMITMENT:"):
            print("[-] Erreur protocole : Réponse inattendue de la TA à l'étape 1.")
            return

        u_hex = reply.split(":")[1]
        print(f"[<-] Engagement u (hex) reçu : {u_hex}")

        # Découpage et reconstruction du Point géométrique u (32 octets u_x || 32 octets u_y)
        u_x = int(u_hex[0:64], 16)
        u_y = int(u_hex[64:128], 16)
        u_point = Point(curve.curve, u_x, u_y)

        # -----------------------------------------------------------------
        # ÉTAPE 2 : Générer le défi aléatoire 'c' (Rôle du Vérificateur)
        # -----------------------------------------------------------------
        # Génération d'un aléa fort de 32 octets (Similaire à /dev/urandom) réduit modulo p
        c_scalar = int.from_bytes(os.urandom(32), byteorder='big') % p
        c_hex = f"{c_scalar:064X}"
        print(f"[*] Défi unique c généré par le Vérificateur : {c_hex}")

        # -----------------------------------------------------------------
        # ÉTAPE 3 : Envoyer c, recevoir la réponse linéaire 'z'
        # -----------------------------------------------------------------
        print(f"[->] Envoi : SEND_CHALLENGE:{c_hex}")
        sock.sendall(f"SEND_CHALLENGE:{c_hex}\n".encode())

        reply = sock.recv(2048).decode().strip()
        if not reply.startswith("RESP_RESPONSE:"):
            print("[-] Erreur protocole : Réponse inattendue de la TA à l'étape 3.")
            return

        z_hex = reply.split(":")[1]
        print(f"[<-] Réponse z (hex) reçue : {z_hex}")
        z_scalar = int(z_hex, 16)

        # -----------------------------------------------------------------
        # ÉTAPE 4 : Vérification mathématique finale de Schnorr
        # -----------------------------------------------------------------
        print("\n=== ÉVALUATION DE L'ÉGALITÉ GÉOMÉTRIQUE ===")
        is_valid = Verify_IZKP_Burkhard(X_identity, u_point, c_scalar, z_scalar)

        print(f">> Résultat de la preuve interactive IZKP : {is_valid}")
        if is_valid:
            print("\n[SUCCÈS]")
        else:
            print("\n[ÉCHEC] Équation géométrique non vérifiée. Clé ou preuve altérée.")

    except Exception as e:
        print(f"[-] Erreur de communication : {e}")
    finally:
        sock.close()
        print("[*] Déconnexion. Session TCP terminée.")

if __name__ == "__main__":
    run_verifier()
