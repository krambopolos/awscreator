import mysql.connector
import paramiko
import subprocess
import logging
import os

# Configuration du logging
log_directory = "./logs"  # Chemin du répertoire de logs relatif au projet
os.makedirs(log_directory, exist_ok=True)
log_file_path = os.path.join(log_directory, "check_servers.log")
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler()
    ]
)

# Fonction pour récupérer les serveurs de la base de données
def get_all_servers():
    servers = []
    try:
        connection = mysql.connector.connect(
            host='94.156.67.171',
            database='rez',
            user='root',
            password='Stupid!Rac00n666'
        )
        cursor = connection.cursor()
        cursor.execute("SELECT id, ip_address, scan_path, key_path, password, aws_access_key, aws_secret_key, aws_region FROM servers WHERE is_deployed = 1")
        for (server_id, ip_address, scan_path, key_path, password, aws_access_key, aws_secret_key, aws_region) in cursor:
            servers.append((
                server_id,
                ip_address,
                scan_path,
                password if password else ""   # Mot de passe par défaut vide
            ))
    except mysql.connector.Error as error:
        logging.error(f"Error: {error}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    return servers

def delete_servers(server_ids):
    try:
        connection = mysql.connector.connect(
            host='94.156.67.171',
            database='rez',
            user='root',
            password='Stupid!Rac00n666'
        )
        cursor = connection.cursor()
        delete_query = "DELETE FROM servers WHERE id = %s"
        for server_id in server_ids:
            cursor.execute(delete_query, (server_id,))
        connection.commit()
        logging.info(f"Deleted {len(server_ids)} servers from the database.")
    except mysql.connector.Error as error:
        logging.error(f"Error deleting servers: {error}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def check_server_with_key(ip_address, key_path):
    """Vérifie la connexion au serveur via SSH avec clé."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, username='ubuntu', key_filename=key_path, timeout=10)
        ssh.close()
        return True
    except Exception as e:
        logging.debug(f"SSH key auth error for {ip_address}: {e}")
        return False

def check_server_with_password(ip_address, password):
    """Vérifie la connexion au serveur via SSH avec mot de passe."""
    try:
        ssh_command = f"sshpass -p {password} ssh -o PreferredAuthentications=password -o StrictHostKeyChecking=no ubuntu@{ip_address} 'exit'"
        result = subprocess.run(ssh_command, shell=True, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        logging.debug(f"SSH password auth error for {ip_address}: {e}")
        return False

def check_servers():
    servers = get_all_servers()
    project_key_path = os.path.abspath("admkey.pub")  # Utiliser la clé privée SSH du projet
    server_statuses = []  # Liste pour stocker les statuts des serveurs
    dead_servers = []  # Liste pour stocker les serveurs inaccessibles

    for server in servers:
        server_id, ip_address, scan_path, password = server
        logging.info(f"Checking server {ip_address}...")

        # Remove the 'ubuntu@' prefix if present
        if ip_address.startswith("ubuntu@"):
            ip_address = ip_address.split("@")[1]

        if os.path.exists(project_key_path):
            if check_server_with_key(ip_address, project_key_path):
                status = f"Server {server_id} ({ip_address}) is live (SSH key)."
                logging.info(status)
                server_statuses.append(status)
            else:
                status = f"Server {server_id} ({ip_address}) is not accessible (SSH key)."
                logging.info(status)
                server_statuses.append(status)
                dead_servers.append(server_id)
        elif password:
            if check_server_with_password(ip_address, password):
                status = f"Server {server_id} ({ip_address}) is live (password)."
                logging.info(status)
                server_statuses.append(status)
            else:
                status = f"Server {server_id} ({ip_address}) is not accessible (password)."
                logging.info(status)
                server_statuses.append(status)
                dead_servers.append(server_id)
        else:
            status = f"No authentication method available for server {server_id} ({ip_address})."
            logging.info(status)
            server_statuses.append(status)
            dead_servers.append(server_id)

    # Afficher le récapitulatif des statuts des serveurs
    logging.info("Recap of server statuses:")
    for status in server_statuses:
        logging.info(status)

    # Demander à l'utilisateur s'il veut supprimer les serveurs inaccessibles
    if dead_servers:
        user_input = input(f"Do you want to delete {len(dead_servers)} inaccessible servers from the database? (yes/no): ").strip().lower()
        if user_input == 'yes':
            delete_servers(dead_servers)

if __name__ == "__main__":
    check_servers()
