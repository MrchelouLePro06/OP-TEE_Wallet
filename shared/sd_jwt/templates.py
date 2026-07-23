import random
import time
from sd_jwt.issuer import SDObj

TEMPLATES = {
    "covid_cert": {
        "claims": lambda holder_jwk: {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vaccination/v1"
            ],
            "type": [
                "VerifiableCredential",
                "VaccinationCertificate"
            ],
            "iss": "https://example.com/issuer",
            "iat": int(time.time()),
            "exp": int(time.time()) + 365 * 86400,
            "name": "COVID-19 Vaccination Certificate",
            "description": "COVID-19 Vaccination Certificate",
            "vct": "https://w3id.org/vaccination/v1",
            "cnf": {
                "jwk": holder_jwk
            },
            "credentialSubject": {
                "type": "VaccinationEvent",
                SDObj("nextVaccinationDate"): "2021-08-16T13:40:12Z",
                SDObj("countryOfVaccination"): "GE",
                SDObj("dateOfVaccination"): "2021-06-23T13:40:12Z",
                SDObj("order"): "3/3",
                SDObj("administeringCentre"): "Praxis Sommergarten",
                SDObj("batchNumber"): "1626382736",
                SDObj("healthProfessional"): "883110000015376",
                "vaccine": {
                    "type": "Vaccine",
                    SDObj("atcCode"): "J07BX03",
                    SDObj("medicinalProductName"): "COVID-19 Vaccine Moderna",
                    SDObj("marketingAuthorizationHolder"): "Moderna Biotech"
                },
                "recipient": {
                    "type": "VaccineRecipient",
                    SDObj("gender"): "Female",
                    SDObj("birthDate"): "1961-08-17",
                    SDObj("givenName"): "Marion",
                    SDObj("familyName"): "Mustermann"
                }
            }
        },
        "selective_claims": [
            "nextVaccinationDate",
            "countryOfVaccination",
            "dateOfVaccination",
            "order",
            "administeringCentre",
            "batchNumber",
            "healthProfessional",
            "atcCode",
            "medicinalProductName",
            "marketingAuthorizationHolder",
            "gender",
            "birthDate",
            "givenName",
            "familyName"
        ]
    },

    "cni": {
        "claims": lambda holder_jwk: {
            "iss": "https://ministere-interieur.gouv.fr",
            "iat": int(time.time()),
            "exp": int(time.time()) + 365 * 86400,
            "vct": "https://credentials.gouv.fr/vct/national-id",
            "cnf": {
                "jwk": holder_jwk
            },
            SDObj("birthdate"): "2004-05-12",
            SDObj("document_number"): "FR987654321",
            SDObj("given_name"): "Jean",
            SDObj("family_name"): "Dupont"
        },
        "selective_claims": ["birthdate", "document_number", "given_name", "family_name"]
    }
}


def get_claims_template(doc_name, holder_jwk):
    if doc_name not in TEMPLATES:
        raise ValueError(f"Modèle '{doc_name}' inconnu.")
    return TEMPLATES[doc_name]["claims"](holder_jwk)


def get_random_required_claims(doc_name):
    """
    Sélectionne aléatoirement entre 2 et MAX claims parmi celles du modèle.
    """
    if doc_name not in TEMPLATES:
        raise ValueError(f"Modèle '{doc_name}' inconnu.")
    
    available = TEMPLATES[doc_name]["selective_claims"]
    
    # Sécurité au cas où la liste contient moins de 2 éléments
    min_count = min(2, len(available))
    max_count = len(available)
    
    # Tirage d'un nombre k entre 2 et Max
    k = random.randint(min_count, max_count)
    
    selected = random.sample(available, k)
    return ",".join(selected)
