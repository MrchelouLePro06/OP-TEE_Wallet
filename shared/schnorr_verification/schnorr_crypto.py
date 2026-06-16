#!/usr/bin/env python3
"""
Module de vérification cryptographique pour les protocoles Schnorr NIZKP et IZKP.
S'appuie sur la courbe NIST P-256 (secp256r1).
"""

import hashlib
import os
from ecdsa import NIST256p
from ecdsa.ellipticcurve import Point

# Configuration globale de la courbe
curve = NIST256p
gen = curve.generator
p = curve.order  # p = n

def verify_nizkp(X, m, u, z, c):
    """
    Vérifie une preuve Non-Interactive (NIZKP) classique.
    """
    u_prime = (gen * z) + (X * (-c % p))

    h = hashlib.sha256()
    h.update(X.x().to_bytes(32, 'big'))
    h.update(X.y().to_bytes(32, 'big'))
    if m:
        h.update(m.encode('utf-8'))
    h.update(u_prime.x().to_bytes(32, 'big'))
    h.update(u_prime.y().to_bytes(32, 'big'))
    c_prime = int(h.hexdigest(), 16) % p

    return c == c_prime

def generate_izkp_challenge():
    """
    Génère un défi 'c' aléatoire fort de 32 octets pour le protocole interactif (IZKP).
    """
    random_bytes = os.urandom(32)
    c_scalar = int.from_bytes(random_bytes, byteorder='big') % p
    return c_scalar 

def verify_izkp_geometry(X, u, c, z):
    """
    Vérifie l'égalité géométrique d'une preuve interactive (IZKP).
    """
    u_prime = (gen * z) + (X * (-c % p))
    return u_prime == u

def verify_multi_attribute_nizkp(X1, X2, msg, z1, z2, c1, c2, mode_str):
    try:
        print("\n--- SERVEUR : ANALYSE INTERNE DE LA VÉRIFICATION ---")
        field = curve.curve.p()
        
        # 1. Calcul des opposés pour la soustraction
        X1_neg = Point(curve.curve, X1.x(), (-X1.y()) % field)
        X2_neg = Point(curve.curve, X2.x(), (-X2.y()) % field)

        # 2. Reconstruction géométrique des engagements temporaires (U')
        U1_prime = (gen * z1) + (X1_neg * c1)
        U2_prime = (gen * z2) + (X2_neg * c2)

        print(f"[SERVEUR-RECONSTRUCT] U1_prime.X = {U1_prime.x():064X}")
        print(f"[SERVEUR-RECONSTRUCT] U1_prime.Y = {U1_prime.y():064X}")
        print(f"[SERVEUR-RECONSTRUCT] U2_prime.X = {U2_prime.x():064X}")
        print(f"[SERVEUR-RECONSTRUCT] U2_prime.Y = {U2_prime.y():064X}")

        # 3. Préparation des dumps de l'oracle de hachage
        h = hashlib.sha256()
        
        # On stocke dans des variables pour pouvoir les print avant le update
        b_X1x = X1.x().to_bytes(32, 'big')
        b_X1y = X1.y().to_bytes(32, 'big')
        b_X2x = X2.x().to_bytes(32, 'big')
        b_X2y = X2.y().to_bytes(32, 'big')
        b_msg = msg.encode('utf-8') if msg else b""
        b_U1x = U1_prime.x().to_bytes(32, 'big')
        b_U1y = U1_prime.y().to_bytes(32, 'big')
        b_U2x = U2_prime.x().to_bytes(32, 'big')
        b_U2y = U2_prime.y().to_bytes(32, 'big')

        print("\n--- TRAIN DE HACHAGE TRANSMIS À L'ORACLE PYTHON ---")
        print(f"1. h.update(X1.x)  -> {b_X1x.hex().upper()}")
        print(f"2. h.update(X1.y)  -> {b_X1y.hex().upper()}")
        print(f"3. h.update(X2.x)  -> {b_X2x.hex().upper()}")
        print(f"4. h.update(X2.y)  -> {b_X2y.hex().upper()}")
        print(f"5. h.update(msg)   -> {b_msg.hex().upper()} ('{msg}')")
        print(f"6. h.update(U1'.x) -> {b_U1x.hex().upper()}")
        print(f"7. h.update(U1'.y) -> {b_U1y.hex().upper()}")
        print(f"8. h.update(U2'.x) -> {b_U2x.hex().upper()}")
        print(f"9. h.update(U2'.y) -> {b_U2y.hex().upper()}")

        # Exécution du hachage
        h.update(b_X1x)
        h.update(b_X1y)
        h.update(b_X2x)
        h.update(b_X2y)
        if msg: h.update(b_msg)
        h.update(b_U1x)
        h.update(b_U1y)
        h.update(b_U2x)
        h.update(b_U2y)
        
        c_global_serveur = int(h.hexdigest(), 16) % p
        print(f"\n[SERVEUR-RESULT] c_global recalculé = {c_global_serveur:064X}")
        print(f"[SERVEUR-REÇU]   c1 reçu du client   = {c1:064X}")
        print(f"[SERVEUR-REÇU]   c2 reçu du client   = {c2:064X}")

        if mode_str == "and":
            res_bool = (c1 == c2 and c1 == c_global_serveur)
            print(f"[SERVEUR-VERDICT] Match logique AND ? -> {res_bool}\n")
            return res_bool
        return False

    except Exception as e:
        print("[CRASH CRYPTO SERVEUR]")
        traceback.print_exc()
        return False