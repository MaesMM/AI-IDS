# Readme NGS-IDS

## Installation

Dans un terminal entrer : 

```bash
git clone [https://github.com/MaesMM/AI-IDS.git](https://github.com/MaesMM/AI-IDS.git)
cd AI-IDS/lab/snort
docker-compose up
```

Pour se connecter au container : 

```bash
docker ps #liste les container actifs
docker exec -it <container name> bash --login
```

## Architecture :

![Architecture](Architecture.png)

## Lancement de Snort dans la console

Par défaut les alerte Snort s’affiche directement dans le terminal utilisé pour lancer le container