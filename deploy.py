import paramiko
import pexpect
import mysql.connector
from mysql.connector import Error
import os

# Configuration des chemins
ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(ROOT_PATH, 'admkey.pub')  # Clé SSH à la racine du projet

def list_existing_servers():
    try:
        connection = mysql.connector.connect(
            host='94.156.67.171',
            database='rez',
            user='root',
            password='Stupid!Rac00n666'
        )
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute("SELECT id, ip_address, instance_id, instance_type, key_path, password, is_deployed FROM servers")
            rows = cursor.fetchall()
            print("Existing servers:")
            for row in rows:
                print(f"ID: {row[0]}, IP Address: {row[1]}, Instance ID: {row[2]}, Instance Type: {row[3]}, Is Deployed: {row[6]}")
            return rows
    except Error as e:
        print(f"Failed to retrieve servers from MySQL table {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

def update_is_deployed(server_id):
    try:
        connection = mysql.connector.connect(
            host='94.156.67.171',
            database='rez',
            user='root',
            password='Stupid!Rac00n666'
        )
        if connection.is_connected():
            cursor = connection.cursor()
            update_query = "UPDATE servers SET is_deployed = TRUE WHERE id = %s"
            cursor.execute(update_query, (server_id,))
            connection.commit()
            print(f"Server {server_id} marked as deployed.")
    except Error as e:
        print(f"Failed to update is_deployed for server {server_id}: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

def deploy_on_existing_server(server_id):
    try:
        connection = mysql.connector.connect(
            host='94.156.67.171',
            database='rez',
            user='root',
            password='Stupid!Rac00n666'
        )
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute("SELECT ip_address, password FROM servers WHERE id = %s", (server_id,))
            row = cursor.fetchone()
            if row:
                ip_address_full, db_password = row
                # Extraire l'adresse IP réelle
                ip_address = ip_address_full.split('@')[-1]
                print(f"Deploying on server {ip_address} with key {KEY_PATH} or password {db_password}")
                if db_password:
                    success = execute_commands_on_instance_with_password(ip_address, db_password)
                else:
                    success = execute_commands_on_instance_with_key(ip_address, KEY_PATH)
                
                if success:
                    update_is_deployed(server_id)
    except Error as e:
        print(f"Failed to retrieve or deploy on server {server_id}: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection is closed")

def execute_commands_on_instance_with_key(ip_address, key_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip_address, username='ubuntu', key_filename=key_path)
        commands = [
            'git clone https://github.com/krambopolos/scans.git /home/ubuntu/scans || true',
            'sudo chmod +x /home/ubuntu/scans/install.sh',
            'sudo chmod -R 777 /home/ubuntu/scans',
            'sudo mkdir -p /home/ubuntu/scans/scans',
            'sudo chmod -R 777 /home/ubuntu/scans/scans',
            'cd /home/ubuntu/scans',
            'ls -l /home/ubuntu/scans',  # Affiche le contenu du répertoire
            '[ -f /home/ubuntu/scans/install.sh ] && echo "install.sh exists and is executable"'
        ]
        for command in commands:
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # Attendre la fin de l'exécution
            print(f"Executing: {command}")
            print(stdout.read().decode(errors='ignore'))  # Utiliser errors='ignore'
            print(stderr.read().decode(errors='ignore'))  # Utiliser errors='ignore'
        
        # Vérifier la sortie du script install.sh en utilisant le chemin absolu
        stdin, stdout, stderr = ssh.exec_command('sudo /home/ubuntu/scans/install.sh')
        stdout.channel.recv_exit_status()
        print(f"Output of install.sh:\n{stdout.read().decode(errors='ignore')}")  # Utiliser errors='ignore'
        print(f"Errors of install.sh:\n{stderr.read().decode(errors='ignore')}")  # Utiliser errors='ignore'

        return True
    except Exception as e:
        print(f"Failed to execute commands on instance {ip_address}: {str(e)}")
        return False
    finally:
        ssh.close()

def execute_commands_on_instance_with_password(ip_address, password):
    try:
        ssh_command = f"sshpass -p '{password}' ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@{ip_address}"
        child = pexpect.spawn(ssh_command)
        child.expect("ubuntu@.*'s password:", timeout=120)
        child.sendline(password)
        child.expect(r'\$', timeout=120)

        commands = [
            'git clone https://github.com/krambopolos/scans.git /home/ubuntu/scans || true',
            'sudo chmod +x /home/ubuntu/scans/install.sh',
            'sudo chmod -R 777 /home/ubuntu/scans',
            'sudo mkdir -p /home/ubuntu/scans/scans',
            'sudo chmod -R 777 /home/ubuntu/scans/scans',
            'cd /home/ubuntu/scans',
            'ls -l /home/ubuntu/scans',  # Affiche le contenu du répertoire
            '[ -f /home/ubuntu/scans/install.sh ] && echo "install.sh exists and is executable"'
        ]
        
        for command in commands:
            child.sendline(command)
            child.expect(r'\$', timeout=300)  # Augmentation du délai d'attente
            print(f"Executing: {command}")
            print(child.before.decode(errors='ignore'))  # Utiliser errors='ignore'
        
        # Vérifier la sortie du script install.sh en utilisant le chemin absolu
        child.sendline('sudo /home/ubuntu/scans/install.sh')
        child.expect(r'\$', timeout=600)  # Temps supplémentaire pour le script
        print(f"Output of install.sh:\n{child.before.decode(errors='ignore')}")  # Utiliser errors='ignore'

        child.sendline("exit")
        child.expect(pexpect.EOF)
        
        return True
    except pexpect.TIMEOUT:
        print(f"Timeout while connecting to instance {ip_address}")
        return False
    except pexpect.EOF:
        print(f"End Of File (EOF) while connecting to instance {ip_address}. This usually means the connection was closed by the remote host.")
        print(child.before.decode(errors='ignore'))  # Utiliser errors='ignore'
        return False
    except Exception as e:
        print(f"Failed to execute commands on instance {ip_address}: {str(e)}")
        return False

def main():
    servers = list_existing_servers()
    server_id = int(input("Enter the ID of the server you want to deploy on: "))
    deploy_on_existing_server(server_id)

if __name__ == "__main__":
    main()
