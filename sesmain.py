import boto3
from botocore.exceptions import ClientError
from rich.console import Console
import getpass

console = Console()

# Liste des régions AWS où SES est disponible
regions = [
    "us-east-1", "us-west-1", "us-west-2", "eu-west-1",
    "eu-central-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "sa-east-1"
]

def test_aws_ses_config(region, access_key_id, secret_access_key):
    try:
        client = boto3.client(
            'ses',
            region_name=region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key
        )
        # Obtenir le quota d'envoi
        quota_response = client.get_send_quota()
        max_24_hour_send = quota_response['Max24HourSend']
        
        if max_24_hour_send > 200:
            console.print(f"✅ [green]Connexion réussie à AWS SES dans la région {region}[/green]")
            console.print(f"Quota d'envoi SES: {max_24_hour_send} emails par 24 heures")
            console.print(f"Emails envoyés dans les dernières 24 heures: {quota_response['SentLast24Hours']}")
            
            # Lister les expéditeurs vérifiés
            identities_response = client.list_identities(IdentityType='EmailAddress')
            verified_senders = identities_response['Identities']
            
            result = f"Region: {region}\nQuota: {max_24_hour_send}\nVerified Senders: {', '.join(verified_senders)}\n"
            return result
        else:
            console.print(f"🔴 [yellow]Région {region} a un quota de {max_24_hour_send}, ce qui est inférieur à 200 emails par 24 heures.[/yellow]")
            return None
    except ClientError as e:
        console.print(f"❌ [red]Échec de connexion à AWS SES dans la région {region}: {e}[/red]")
        return None

def main():
    # Demander les clés AWS à l'utilisateur
    access_key_id = input("Entrez votre AWS Access Key ID: ")
    secret_access_key = getpass.getpass("Entrez votre AWS Secret Access Key: ")

    results = []

    for region in regions:
        console.print(f"🔍 [yellow]Test de la région {region} pour la clé {access_key_id}...[/yellow]")
        result = test_aws_ses_config(region, access_key_id, secret_access_key)
        if result:
            results.append(result)

    # Enregistrement des résultats dans un fichier texte
    with open('aws_ses_results.txt', 'w') as f:
        for result in results:
            f.write(result + "\n")

    console.print("🏁 [blue]Test des clés AWS SES terminé. Résultats enregistrés dans aws_ses_results.txt[/blue]")

if __name__ == "__main__":
    main()
