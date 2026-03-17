# network-audit-tool
Professional network scan tool with GUI, PDF/DOCX reports


# Network Audit Tool Pro

Network "Audit Tool Pro" est un outil professionnel pour scanner rapidement vos machines et réseaux.  
Il permet de détecter les services sur les ports, générer des rapports PDF et Word, et offre une interface graphique intuitive.

---

## Fonctionnalités

- Scan "ultra-rapide"(1000 connexions simultanées) avec `asyncio`.
- Détection de "plus de 100 services connus"" par ports.
- Scanner "IP unique ou réseau CIDR".
- Sélection des ports via **checkbox** dans la GUI.
- "Priorisation"" des ports les plus utilisés.
- Export automatique des résultats en "PDF et DOCX".
- "Interface graphique tout-en-un" (PyQt6).
- Résultats affichés directement dans la GUI, lisibles et clairs.

---

## Capture d’écran (exemple GUI)

![Screenshot](screenshot.png)  
> Entrer IP ou réseau, sélectionner les ports, puis cliquer sur "Start Scan".

---

## Installation

### 1️⃣ Cloner le dépôt

```bash
git clone https://github.com/KAD78/network-audit-tool.git
cd network-audit-tool
````


### 2️⃣ Installer les dépendances

```bash
pip install -r requirements.txt
```

**Requirements** :

* Python 3.10+
* PyQt6
* reportlab
* python-docx

---

## Utilisation

### Lancer l’outil GUI

```bash
python main.py
```

### Étapes dans la GUI

1. Entrer l’IP ou réseau CIDR à scanner (ex: `192.168.1.1` ou `192.168.1.0/24`).
2. Sélectionner les ports à scanner (pré-sélection des ports courants).
3. Cochez PDF/DOCX si vous voulez générer un rapport.
4. Cliquer sur "Start Scan".
5. Les résultats s’affichent dans la zone texte et les fichiers PDF/DOCX sont générés automatiquement.

---

## Exemple de scan dans GUI

```
192.168.1.1:22 -> SSH
192.168.1.1:80 -> HTTP
192.168.1.1:443 -> HTTPS
PDF report generated: scan_report.pdf
DOCX report generated: scan_report.docx
```

---

---

## Structure du projet

```text
network-audit-tool/
├── main.py          # Code principal, GUI et scan réseau
├── requirements.txt # Dépendances Python
├── README.md        # Documentation
└── screenshot.png   # Exemple GUI (optionnel)
```

---

## Contribution

* Fork le projet
* Crée une branche feature : `git checkout -b feature/AmazingFeature`
* Commit tes changements : `git commit -m 'Add some feature'`
* Push sur la branche : `git push origin feature/AmazingFeature`
* Ouvre une Pull Request sur GitHub

---

## Licence

Ce projet est sous licence MIT.
Vous êtes libre de l’utiliser, modifier et partager.

---
Prêt à scanner ton réseau rapidement et générer des rapports professionnels !
