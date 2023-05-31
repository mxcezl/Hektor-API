# Utilisez une image de base contenant Python
FROM python:3.9

# Copiez le code source de l'API Flask dans le conteneur
COPY . /app

# Définir le répertoire de travail
WORKDIR /app

# Installation des dépendances de l'API Flask
RUN pip install https://github.com/PaulSec/API-dnsdumpster.com/archive/master.zip --user
RUN pip install -r requirements.txt

# Exposez le port 5000 pour accéder à l'API Flask
EXPOSE 5000

# Commande de démarrage pour lancer l'API Flask
CMD ["python", "app.py"]
