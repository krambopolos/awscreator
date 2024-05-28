# Utiliser une image officielle de Python comme image de base
FROM python:3.9-slim

# Installer sshpass et les dépendances nécessaires
RUN apt-get update && apt-get install -y sshpass

# Mettre à jour pip
RUN pip install --upgrade pip

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier les fichiers requirements.txt dans le conteneur
COPY requirements.txt requirements.txt

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le code source dans le répertoire de travail
COPY . .

# Exposer le port 5000 (ou un autre port si votre application en utilise un différent)
EXPOSE 5000

# Définir la commande par défaut à exécuter lorsque le conteneur démarre
CMD ["python", "main.py"]
