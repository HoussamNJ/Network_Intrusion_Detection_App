# Network Intrusion Detection System

Cette application JavaFX permet de surveiller le trafic réseau en temps réel et de détecter les activités suspectes. Elle offre une interface graphique intuitive pour visualiser les connexions réseau et les alertes de sécurité.

## Fonctionnalités

- Surveillance en temps réel du trafic réseau
- Détection des attaques par déni de service (DoS)
- Détection des scans de ports
- Visualisation graphique du trafic entrant et sortant
- Tableau détaillé des paquets réseau
- Système d'alertes pour les activités suspectes
- Compteur de connexions actives

## Prérequis

- Java 17 ou supérieur
- Maven
- Bibliothèque WinPcap (Windows) ou libpcap (Linux/macOS)

## Installation

1. Installez WinPcap (Windows) ou libpcap (Linux/macOS)
   - Windows : Téléchargez et installez [WinPcap](https://www.winpcap.org/install/)
   - Linux : `sudo apt-get install libpcap-dev`
   - macOS : `brew install libpcap`

2. Clonez le dépôt :
   ```bash
   git clone [URL_DU_REPO]
   cd network-intrusion-detection
   ```

3. Compilez le projet :
   ```bash
   mvn clean install
   ```

## Utilisation

1. Lancez l'application :
   ```bash
   mvn javafx:run
   ```

2. L'interface affichera :
   - Un graphique montrant le trafic réseau en temps réel
   - Un tableau des paquets détectés
   - Une zone d'alertes pour les activités suspectes
   - Le nombre de connexions actives

## Configuration

Les seuils de détection peuvent être ajustés dans la classe `NetworkMonitorService` :
- `DOS_THRESHOLD` : Seuil pour la détection des attaques DoS
- `PORT_SCAN_THRESHOLD` : Seuil pour la détection des scans de ports
