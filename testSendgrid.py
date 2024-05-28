import os
import requests

# Remplacez par votre clé API SendGrid
SENDGRID_API_KEY = ''

# URL de l'API pour lister les Sender Identities
url = "https://api.sendgrid.com/v3/senders"

# Headers de la requête
headers = {
    "Authorization": f"Bearer {SENDGRID_API_KEY}",
    "Content-Type": "application/json"
}

def list_sender_identities():
    """
    Liste tous les Sender Identities de votre compte SendGrid.

    Returns:
    list: Une liste de tous les Sender Identities.
    """
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            senders = response.json()
            return senders
        else:
            print(f"Erreur: {response.status_code}")
            print(response.text)
            return []
    except Exception as e:
        print(f"Exception: {e}")
        return []

# Utilisation de la fonction
senders = list_sender_identities()

# Affichage des Sender Identities
for sender in senders:
    print(f"ID: {sender['id']}, Nom: {sender['nickname']}, Email: {sender['from']['email']}")
