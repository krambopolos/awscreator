import mysql.connector
import paramiko
import subprocess
import logging
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackQueryHandler, CallbackContext, ConversationHandler

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

# Conversation states
ASK_DELETE_ID = range(1)

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
        logging.error(f"⚠️ Erreur : {error}")
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
        logging.info(f"🗑️ Supprimé {len(server_ids)} serveurs de la base de données.")
    except mysql.connector.Error as error:
        logging.error(f"⚠️ Erreur lors de la suppression des serveurs : {error}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def delete_server_by_id(server_id):
    try:
        connection = mysql.connector.connect(
            host='94.156.67.171',
            database='rez',
            user='root',
            password='Stupid!Rac00n666'
        )
        cursor = connection.cursor()
        delete_query = "DELETE FROM servers WHERE id = %s"
        cursor.execute(delete_query, (server_id,))
        connection.commit()
        logging.info(f"🗑️ Supprimé le serveur {server_id} de la base de données.")
    except mysql.connector.Error as error:
        logging.error(f"⚠️ Erreur lors de la suppression du serveur {server_id} : {error}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def execute_commands(ssh):
    """Exécute les commandes nécessaires sur le serveur connecté via SSH et renvoie les résultats."""
    commands = [
        'cd ~/scans && sudo git stash && sudo git pull',
        'cd ~/scans && sudo docker-compose down',
        'cd ~/scans && sudo docker-compose up --build -d'
    ]
    results = []
    for command in commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()  # Attendre que la commande soit terminée
        stdout_output = stdout.read().decode()
        stderr_output = stderr.read().decode()
        results.append({
            'command': command,
            'exit_status': exit_status,
            'stdout': stdout_output,
            'stderr': stderr_output
        })
        logging.info(stdout_output)
        logging.error(stderr_output)
    return results

def execute_commands_on_servers(servers):
    """Exécute les commandes nécessaires sur tous les serveurs en direct via SSH et collecte les résultats."""
    update_results = []
    for server in servers:
        server_id, ip_address, scan_path, password = server
        server_result = {
            'server_id': server_id,
            'ip_address': ip_address,
            'success': False,
            'details': []
        }
        try:
            if password:
                ssh_command = f"sshpass -p {password} ssh -o PreferredAuthentications=password -o StrictHostKeyChecking=no ubuntu@{ip_address} 'cd ~/scans && sudo git stash && sudo git pull && sudo docker-compose down && sudo docker-compose up --build -d'"
                result = subprocess.run(ssh_command, shell=True, capture_output=True, text=True, timeout=30)
                server_result['details'].append({
                    'command': ssh_command,
                    'exit_status': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                })
                if result.returncode == 0:
                    server_result['success'] = True
            else:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip_address, username='ubuntu', key_filename=scan_path, timeout=10)
                server_result['details'] = execute_commands(ssh)
                ssh.close()
                server_result['success'] = True
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            error_message = f"🚫 Aucune connexion valide à {ip_address}. Assurez-vous que SSH est en cours d'exécution et accessible."
            logging.error(error_message)
            server_result['details'].append({'error': error_message})
        except paramiko.ssh_exception.AuthenticationException as e:
            error_message = f"🔑 Authentification échouée pour {ip_address}. Vérifiez les identifiants."
            logging.error(error_message)
            server_result['details'].append({'error': error_message})
        except Exception as e:
            error_message = f"⚠️ Connexion SSH échouée pour {ip_address} : {str(e)}"
            logging.error(error_message)
            server_result['details'].append({'error': error_message})
        update_results.append(server_result)
    return update_results

def check_server_with_key(ip_address, key_path):
    """Vérifie la connexion au serveur via SSH avec clé."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, username='ubuntu', key_filename=key_path, timeout=10)
        ssh.close()
        return True
    except Exception as e:
        logging.debug(f"🔑 Erreur d'authentification par clé SSH pour {ip_address} : {e}")
        return False

def check_server_with_password(ip_address, password):
    """Vérifie la connexion au serveur via SSH avec mot de passe."""
    try:
        ssh_command = f"sshpass -p {password} ssh -o PreferredAuthentications=password -o StrictHostKeyChecking=no ubuntu@{ip_address} 'exit'"
        result = subprocess.run(ssh_command, shell=True, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception as e:
        logging.debug(f"🔑 Erreur d'authentification par mot de passe pour {ip_address} : {e}")
        return False

def check_servers():
    servers = get_all_servers()
    project_key_path = os.path.abspath("admkey.pub")  # Utiliser la clé privée SSH du projet
    server_statuses = []  # Liste pour stocker les statuts des serveurs
    live_servers = []     # Liste pour stocker les serveurs en direct
    dead_servers = []     # Liste pour stocker les serveurs inaccessibles

    for server in servers:
        server_id, ip_address, scan_path, password = server
        logging.info(f"🖥️ Vérification du serveur {ip_address}...")

        # Remove the 'ubuntu@' prefix if present
        if ip_address.startswith("ubuntu@"):
            ip_address = ip_address.split("@")[1]

        if os.path.exists(project_key_path):
            if check_server_with_key(ip_address, project_key_path):
                status = f"🟢 Serveur {server_id} ({ip_address}) est en ligne (clé SSH)."
                logging.info(status)
                server_statuses.append(status)
                live_servers.append(server)
            else:
                status = f"🔴 Serveur {server_id} ({ip_address}) est inaccessible (clé SSH)."
                logging.info(status)
                server_statuses.append(status)
                dead_servers.append(server)
        elif password:
            if check_server_with_password(ip_address, password):
                status = f"🟢 Serveur {server_id} ({ip_address}) est en ligne (mot de passe)."
                logging.info(status)
                server_statuses.append(status)
                live_servers.append(server)
            else:
                status = f"🔴 Serveur {server_id} ({ip_address}) est inaccessible (mot de passe)."
                logging.info(status)
                server_statuses.append(status)
                dead_servers.append(server)
        else:
            status = f"🔴 Aucun méthode d'authentification disponible pour le serveur {server_id} ({ip_address})."
            logging.info(status)
            server_statuses.append(status)
            dead_servers.append(server)

    return server_statuses, live_servers, dead_servers

def start(update: Update, context: CallbackContext):
    keyboard = [
        [InlineKeyboardButton("📋 Lister", callback_data='list_servers')],
        [InlineKeyboardButton("🗑️ Supprimer", callback_data='delete_specific_server')],
        [InlineKeyboardButton("🔄 Mettre à jour", callback_data='execute_commands')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if update.message:
        update.message.reply_text('Bonjour! Choisissez une option:', reply_markup=reply_markup)
    elif update.channel_post:
        context.bot.send_message(chat_id=update.channel_post.chat_id, text='Bonjour! Choisissez une option:', reply_markup=reply_markup)

def list_servers(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    query.edit_message_text(text="📋 Listing des serveurs en cours...")
    server_statuses, live_servers, dead_servers = check_servers()
    message = "📋 **Liste des serveurs :**\n\n"
    for index, status in enumerate(server_statuses, start=1):
        emoji = "🟢" if "en ligne" in status else "🔴"
        message += f"{emoji} {index}. {status}\n"
    
    keyboard = [
        [InlineKeyboardButton("🗑️ Tous les morts", callback_data='delete_all_dead_servers')],
        [InlineKeyboardButton("🗑️ Supprimer un", callback_data='delete_specific_server')],
        [InlineKeyboardButton("🔄 Mettre à jour", callback_data='execute_commands')]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    query.edit_message_text(text=message, reply_markup=reply_markup, parse_mode='Markdown')

def execute_commands_handler(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    query.edit_message_text(text="🔄 Mise à jour des serveurs en cours...")

    server_statuses, live_servers, _ = check_servers()
    update_results = execute_commands_on_servers(live_servers)
    
    message = "📋 **Rapport de mise à jour des serveurs :**\n\n"
    for result in update_results:
        status_emoji = "🟢" if result['success'] else "🔴"
        message += f"{status_emoji} Serveur {result['server_id']} ({result['ip_address']})\n"
        if result['success']:
            for detail in result['details']:
                message += f"  ✅ Commande : {detail['command']} - Statut : {detail['exit_status']}\n"
        else:
            for detail in result['details']:
                message += f"  ⚠️ Erreur : {detail['error']}\n"

    query.edit_message_text(text=message, parse_mode='Markdown')

def delete_all_dead_servers_handler(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    query.edit_message_text(text="🗑️ Suppression des serveurs morts en cours...")

    _, _, dead_servers = check_servers()
    dead_server_ids = [server[0] for server in dead_servers]
    delete_servers(dead_server_ids)
    
    query.edit_message_text(text="🗑️ Tous les serveurs morts ont été supprimés de la base de données.")

def delete_specific_server(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    query.edit_message_text(text="🗑️ Veuillez entrer l'ID du serveur que vous souhaitez supprimer.")
    return ASK_DELETE_ID

def delete_server_by_id_handler(update: Update, context: CallbackContext):
    server_id = int(update.message.text)
    update.message.reply_text(text="🗑️ Suppression en cours...")
    delete_server_by_id(server_id)
    update.message.reply_text(f"🗑️ Le serveur {server_id} a été supprimé de la base de données.")
    return ConversationHandler.END

def cancel(update: Update, context: CallbackContext):
    update.message.reply_text('❌ Action annulée.')
    return ConversationHandler.END

def handle_channel_post(update: Update, context: CallbackContext):
    message = update.channel_post.text
    if '/start' in message:
        start(update, context)

def main():
    updater = Updater("6795066175:AAGffV4cN_nwKC2f2in4Utz51Ibie8NXxcA", use_context=True)
    dispatcher = updater.dispatcher

    conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(delete_specific_server, pattern='delete_specific_server')],
        states={
            ASK_DELETE_ID: [MessageHandler(Filters.text & ~Filters.command, delete_server_by_id_handler)]
        },
        fallbacks=[CommandHandler('cancel', cancel)]
    )

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CallbackQueryHandler(list_servers, pattern='list_servers'))
    dispatcher.add_handler(CallbackQueryHandler(execute_commands_handler, pattern='execute_commands'))
    dispatcher.add_handler(CallbackQueryHandler(delete_all_dead_servers_handler, pattern='delete_all_dead_servers'))
    dispatcher.add_handler(conv_handler)
    dispatcher.add_handler(MessageHandler(Filters.text & Filters.chat_type.channel, handle_channel_post))

    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
