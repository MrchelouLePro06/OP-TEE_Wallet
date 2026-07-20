#!/usr/bin/env python3
import json

def get_payload_template(template_name, holder_jwk):
    """
    Retourne (payload_dict, list_of_b64url_disclosures) synchronisés.
    Les clés à l'intérieur des disclosures matchent exactement la structure du document.
    """
    
    # -----------------------------------------------------------------
    # MODÈLE 1 : CNI FRANÇAISE (ALICE MARTIN)
    # -----------------------------------------------------------------
    if template_name in ["cni", "cni_fr"]:
        payload = {
            "iss": "https://ministere-interieur.gouv.fr",
            "vct": "https://credentials.gouv.fr/vct/national-id",
            "given_name": "Alice",
            "family_name": "Martin",
            "cnf": {"jwk": holder_jwk},
            "_sd_alg": "sha-256"
        }
        # Les clés 'birthdate' et 'document_number' matchent ton filtrage TA
        disclosures = [
            "WyJ1dTROcXRKUm9fTGUzd2VIcFB2d2F3IiwgImJpcnRoZGF0ZSIsICIyMDA0LTA1LTEyIl0",
            "WyJEOGxtOU1VamhFSTFoRndOeGlCZGZnIiwgImRvY3VtZW50X251bWJlciIsICJGUjk4NzY1NDMyMSJd"
        ]
        return payload, disclosures

    # -----------------------------------------------------------------
    # MODÈLE 2 : ADRESSE STRUCTURÉE
    # -----------------------------------------------------------------
    elif template_name == "structured_address":
        payload = {
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": {
                "_sd": [
                    "Ek2zRVvXFVw3-EHiBK3Lsssjv1qbotW_sp2ju03sq4s",
                    "evzKfw0XVp9x1Br5IZrl1c-t0HlrGo6uvYY7qIUhqXA",
                    "fd4ull64_NWEHwPFiE87blw2sjDjtyZW-Ho_DuZUpyE",
                    "jBYSBZ7gJpwMja_eJcWuVHJFAmz1fF7xOc6Fb0dGGH8"
                ]
            },
            "cnf": {"jwk": holder_jwk},
            "_sd_alg": "sha-256"
        }
        # Les clés matchent l'objet address
        disclosures = [
            "WyI0M2FlZjk4Y2FlYmEyYWIxIiwgInN0cmVldF9hZGRyZXNzIiwgIjEyMyBNYWluIFN0Il0",
            "WyI1ZTViN2M5YThkZjBhYmMyIiwgImxvY2FsaXR5IiwgIkFueXRvd24iXQ"
        ]
        return payload, disclosures
        
    # -----------------------------------------------------------------
    # MODÈLE 3 : COMPLEXE STRUCTURÉ (VERIFICATIONS AML)
    # -----------------------------------------------------------------
    elif template_name == "complex_structured":
        payload = {
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "verified_claims": {
                "verification": {
                    "_sd": [
                        "EWyCO8OLCdLjs5Ql_jzDe7qb4l8OhXPVAq_Izkuk3O0",
                        "V5Gl6tnpcLCs6g1NUe1n4ge3qF5fNKlFeHcW5kFqZIM"
                    ],
                    "trust_framework": "de_aml",
                    "evidence": [{"...": "YnL4kGryd2_kNdmiqCzy8S-DV4IeTDiIr6Bj0tPDU6c"}]
                },
                "claims": {
                    "_sd": [
                        "igi72f_oFoMVxtaxzSvh-UIewL7b9qI32-Ra3xqUJy4",
                        "2waOsSXu1OVuYUnaPmFJqCzzYgio_AIvSimdAt-GPgU",
                        "vGxaWbmmhr9oR4ZG2u0LUWJBWwbwJVluMhUvvqnLnDU"
                    ]
                }
            },
            "cnf": {"jwk": holder_jwk},
            "_sd_alg": "sha-256"
        }
        # Les clés matchent l'objet interne claims
        disclosures = [
            "WyI2YTU0ZTNkMmYxOGJjOWEyIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
            "WyI3YjI0Yzg5M2FmZGUxMGMzIiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        ]
        return payload, disclosures
        
    # =========================================================================
    # MODÈLE 5 : CERTIFICAT DE VACCINATION COVID-19 (STRUCTURE MULTI-NIVEAUX)
    # =========================================================================
    elif template_name == "covid_cert":
        payload = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vaccination/v1"
            ],
            "type": [
                "VerifiableCredential",
                "VaccinationCertificate"
            ],
            "issuer": "https://example.com/issuer",
            "issuanceDate": "2023-02-09T11:01:59Z",
            "expirationDate": "2028-02-08T11:01:59Z",
            "name": "COVID-19 Vaccination Certificate",
            "description": "COVID-19 Vaccination Certificate",
            "cnf": {"jwk": holder_jwk},  # Injection dynamique de la clé de la TA
            "credentialSubject": {
                "type": "VaccinationEvent",
                "_sd": [
                    "AN8fGQH71sxVicG6kpzMeuC6DUjWYweTbzo2YENbPIw",
                    "W7PJCiGTkD6698JubYrfE9Nw0s9s2Qufo_w-rbGglso",
                    "3NQAz_q5LUUdLssevda4iAVyHFQXrIr8azIxD1pzVF4",
                    "hwSSXnJOxODS4g0272WSRvyfBUaI7gEFb-bgiQE4Pv8",
                    "ew2bZj2drxmdWsDLgAgORgAflpO_MjwJ6BqRyyMfAiA",
                    "MXrkHIROu1-CUMqgTmpJApw1QKiG-Ev4E3BlMI8dLOs",
                    "kmq2TibfEvdQ59sv6rzINltNqvpJfOG1VmLl3gMZseg"
                ],
                "vaccine": {
                    "type": "Vaccine",
                    "_sd": [
                        "jc7VUrPqLJ1uCF3jo0U5eMsMl2sdtjEf2k2J2GML3lo",
                        "NnweRuqvhENsc-yYOVa7tBSXnmwn8v4Y3d00cC1M6hI",
                        "-aWn6C2F8nsfTQEpMotE0D0YsLN6XRCYwlKazyBGxgk"
                    ]
                },
                "recipient": {
                    "type": "VaccineRecipient",
                    "_sd": [
                        "Ck24z45Hi1vUfNt44qKLmS1gnbRqPvmSmyMaW9otpbU",
                        "A7jZlA13I-9fbqydsUE1zprrw9GVW17q9JgYgru4VcQ",
                        "pTPGEA7YCTuIGF2uEiykOSLE7e9QHtk1-dw6PKd1A_w",
                        "YXlycX6aWB5LGdyhdaH-rq_ze34ALbh4FyVwkpuf4n0"
                    ]
                }
            },
            "_sd_alg": "sha-256"
        }
        # Disclosures prêtes et synchronisées pour les structures imbriquées
        disclosures = [
            # Niveau 1 : Infos de l'événement (ex: date de vaccination, pays)
            "WyI0M2FlZjk4Y2FlYmEiLCAiZGF0ZSIsICIyMDIzLTAyLTAxIl0",
            "WyI1ZTViN2M5YThkZjBhIiwgImNvdW50cnkiLCAiRlIiXQ",
            # Niveau 2 : Infos sur le vaccin (Masqué sous vaccine._sd)
            "WyI2YTU0ZTNkMmYxOGIiLCAidmFjY2luZU5hbWUiLCAiQ29taXJuYXR5IC0gUGZpemVyIl0",
            # Niveau 2 : Infos sur le destinataire (Masqué sous recipient._sd)
            "WyI3YjI0Yzg5M2FmZGUiLCAicGF0aWVudE5hbWUiLCAiSm9obiBEb2UiX]"
        ]
        return payload, disclosures
