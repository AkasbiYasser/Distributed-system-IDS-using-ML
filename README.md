# Dévelopemment d'un systéme distribué de  Détection d'Intrusion Basé sur le Machine Learning

Ce projet implémente un système de détection d'intrusion (IDS) en utilisant des modèles de Machine Learning pour analyser le trafic réseau et détecter des anomalies.

## Fonctionnalités Principales

- **Prétraitement des Données** : Normalisation et nettoyage des données avec pandas et scikit-learn.
- **Sélection de Caractéristiques** : Utilisation d'une forêt aléatoire pour extraire les caractéristiques les plus influentes.
- **Modèles de Classification** : Implémentation et comparaison de modèles Random Forest et SVM.
- **Déploiement** : Application du modèle le plus précis sur les nouvelles données pour la classification.
- **Notifications et Blocage** : Utilisation de Telegram pour notifier et bloquer les attaques en temps réel.

## Outils Utilisés

- **Python**
- **Google Colab**
- **MySQL**

## Structure du Projet

- **Prétraitement** : Scripts pour le nettoyage et la normalisation des données.
- **Modélisation** : Scripts pour la création et l'évaluation des modèles de Machine Learning.
- **Déploiement** : Scripts pour l'application des modèles et la gestion des alertes.