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
    """
    Vérifie une preuve multi-attribut (AND/OR) en parfaite conformité
    avec les appels TEE_DigestUpdate de la TA OP-TEE.
    """
    try:
        # 1. Réduction géométrique : Calcul des engagements théoriques U1' et U2'
        U1_prime = (gen * z1) + (X1 * (-c1 % p))
        U2_prime = (gen * z2) + (X2 * (-c2 % p))

        # 2. Reconstitution de l'oracle SHA256 (Ordre et variables stricts de la TA)
        h = hashlib.sha256()
        h.update(X1.x().to_bytes(32, 'big'))  # pub_X1_bytes_x
        h.update(X2.x().to_bytes(32, 'big'))  # pub_X2_bytes_x
        if msg:
            h.update(msg.encode('utf-8'))     # msg
        h.update(U1_prime.x().to_bytes(32, 'big'))  # u1_bytes_x
        h.update(U2_prime.x().to_bytes(32, 'big'))  # u2_bytes_x
        
        c_global_serveur = int(h.hexdigest(), 16) % p

        # 3. Vérification des contraintes du prédicat logique
        if mode_str == "and":
            # Mode AND : c1 et c2 doivent être égaux au défi global de l'oracle
            return c1 == c2 and c1 == c_global_serveur
        elif mode_str == "or":
            # Mode OR : la somme des défis doit être égale au défi global de l'oracle
            return (c1 + c2) % p == c_global_serveur
        else:
            return False

    except Exception as e:
        raise RuntimeError(f"Erreur interne lors de la vérification multi-attribut : {str(e)}")