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
    Vérifie une preuve Non-Interactive (NIZKP) avec l'heuristique de Fiat-Shamir.
    Le défi 'c' doit correspondre au hachage SHA256 des données transmises.
    """
    # Recalcul de l'engagement géométrique théorique u_prime
    u_prime = (gen * z) + (X * (-c % p))

    # Recalcul du défi attendu via le hachage SHA256 (Fiat-Shamir)
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
    Il sera envoyé au client pour générer le z.
    """
    random_bytes = os.urandom(32)
    c_scalar = int.from_bytes(random_bytes, byteorder='big') % p
    return c_scalar 

def verify_izkp_geometry(X, u, c, z):
    """
    Vérifie l'égalité géométrique d'une preuve interactive (IZKP).
    Équation de Burkhard : u' == (z * G) - (c * X)
    """
    u_prime = (gen * z) + (X * (-c % p))
    return u_prime == u
