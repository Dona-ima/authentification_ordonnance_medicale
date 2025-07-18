# 💊 Authentificateur d'ordonnances médicales

API de gestion des ordonnances médicales avec authentification par rôles (patients, médecins, pharmaciens, super admin). Signatures numériques, QR codes, mises à jour sécurisées et archivage intelligent.

---

## 🚀 Fonctionnalités principales

- 🔐 Authentification via JWT (patients, médecins, pharmaciens, super admin)
- 📝 Création et signature des ordonnances par les médecins
- 📷 Vérification des ordonnances par QR code côté pharmacie
- 💊 Mise à jour des quantités de médicaments vendus
- 📦 Archivage automatique des ordonnances côté patient
- 🧾 Historique des ventes par pharmacie
- 🧠 Double signature (médecin + pharmacie)
- 🔍 Accès administrateur aux archives, logs et pharmacies

---

## 🧱 Technologies
- **FastAPI**
- **Firebase Admin SDK (Firestore)**
- **Ed25519** pour les signatures numériques
- **Python 3.08+**

---

## 🛠️ Installation

```bash
# Clone le repo
$ git clone https://github.com/Dona-ima/authentification_ordonnance_medicale.git
$ cd prescription-api

# Crée l’environnement virtuel
$ python -m venv venv
$ source venv/bin/activate  # ou venv\Scripts\activate sous Windows

# Installe les dépendances
$ pip install -r requirements.txt
```

Créer un fichier `.env` pour stocker les variables Firebase :
```env
SECRET_KEY= Your secret key here
ALGORITHM= Your Algorithm here
ACCESS_TOKEN_EXPIRE_MINUTES= Your expiration time in minutes here
```

---

## 🧑‍⚕️ Création d’un super admin (exécuter une seule fois)

```bash
python scripts/create_super_admin.py
```

---

## 🚀 Lancer le serveur

```bash
uvicorn main:app --reload
```
Interface Swagger : `http://127.0.0.1:8000/docs`
---

## 🛡️ Admin

### 🛡️ Admin Enregistrement d'un patient par l'admin

```http
POST /admin/register_patient
```

**Body** 
```json
{
    "first_name": "John", 
    "last_name": "Doe",
    "email": "newpatient@gmail.com",
    "phone": "1234567890",
    "city": "Cotonou",
    "npi": "33333333",
    "password": "1234"
}
```

### 🛡️ Admin - Enregistrement d'un médecin par l'admin

```http
POST /admin/register_doctor
```

**Body** 
```json
{
    "first_name": "François", 
    "last_name": "Dupont",
    "email": "newdoctor@gmail.com",
    "phone": "2345678901",
    "city": "Cotonou",
    "npi": "11111111",
    "password": "12"
}
```
### 🛡️ Admin - Enregistrement d'une pharmacie par l'admin

```http
POST /admin/register_pharmacy
```

**Body** 
```json
{
    "name": "Pharmacie La Concorde", 
    "email": "laConcorde@gmail.com",
    "phone": "3456789012",
    "city": "Abomey-Calavi",
    "serial_number": "00000001",
    "password": "12"
}

```

### 🛡️ Admin – Voir les patients
```http
GET /admin/patients
```

### 🛡️ Admin – Voir les détails d'un patient donné
```http
GET /admin/patients/{npi}
```

### 🛡️ Admin – Voir les ordonnances en cours de validité d'un patient donné
```http
GET /admin/patients/{npi}/prescriptions
```

### 🛡️ Admin – Voir les ordonnances archivées d’un patient
```http
GET /admin/patients/{npi}/archived_prescriptions
```

### 🛡️ Admin – Voir l'historique d'achat de médicament lié à une ordonnance archivée d'un patient donné
```http
GET /admin/patients/{npi}/archived_prescriptions/{prescription_id}/logs
```

### 🛡️ Admin Supprimer un Patient
```http
DELETE /admin/patients/{npi}/delete
```

### 🛡️ Admin – Voir les médecins
```http
GET /admin/doctors
```

### 🛡️ Admin – Voir les détails d'un médecin donné
```http
GET /admin/doctors/{npi}
```

### 🛡️ Admin – Voir les ordonnances prescrites par un médecin donné
```http
GET /admin/doctors/{npi}/prescriptions
```

### 🛡️ Admin - Supprimer un médecin
```http
DELETE /admin/doctors/{npi}/delete
```

### 🛡️ Admin – Liste des pharmacies
```http
GET /admin/pharmacies/
```

### 🛡️ Admin – Infos d’une pharmacie
```http
GET /admin/pharmacies/{serial_number}
```

### 🛡️ Admin – Historique de vente d’une pharmacie
```http
GET /admin/pharmacies/{serial_number}/sales_history
```

### 🛡️ Admin – Supprimer une Pharmacie
```http
DELETE /admin/pharmacies/{npi}/delete
```

---
  
## 👨‍⚕️ Médecin

### 👨‍⚕️ Médecin – Connexion
```http
POST /login_doctor
```

**Body**
```json
{
    "npi": "11111111",
    "password": "12"
}
```
  
### 👨‍⚕️ Médecin – Déconnexion
```http
POST /doctor/logout_doctor
```

### 👨‍⚕️ Médecin – Voir son profil 
```http
GET /doctor/me
```
  
### 👨‍⚕️ Médecin – Créer une ordonnance
```http
POST /doctors/create_prescription
```

**Body**
```json
{
  "data": {
    "patient_first_name": "John",
    "patient_last_name": "Doe",
    "patient_npi": "33333333",
    "prescription_details": [
      {
        "medication_name": "Paracétamol",
        "dosage": "500mg",
        "frequency": "3 fois/jour",
        "duration": "5 jours",
        "prescribed_quantity": 2,
        "instructions": "À prendre après les repas"
      },
      {
        "medication_name": "Amoxiciline",
        "dosage": "500mg",
        "frequency": "2 fois/jour",
        "duration": "7 jours",
        "prescribed_quantity": 2,
        "instructions": "À prendre après les repas"
      }
    ]
  },
  "password": "12"
}

```

### 👨‍⚕️ Médecin – Voir ordonnances prescrites
```http
GET /doctor/prescriptions
```

---

## 💊 Pharmacie

### 💊 Pharmacie – Connexion
```http
POST /login_pharmacy
```

**Body**
```json
{
    "serial_number": "00000001",
    "password": "12"
}

```
  
### 💊 Pharmacie – Déconnexion
```http
POST /pharmacy/logout_pharmacy
```

### 💊 Pharmacie – Voir son profil 
```http
GET /pharmacy/me
```
  
### 💊 Pharmacie – Vérifier une ordonnance via QR code
```http
POST /pharmacy/verify_prescription
```

**Body**
```json
{
  "message": { ... },
  "signature": "base64_signature",
  "public_key": "base64_public_key"
}
```

### 💊 Pharmacien – Mettre à jour une ordonnance
```http
POST /pharmacy/update_prescription
```
**Body**
```json
{
  "prescription_id": "uuid",
  "patient_npi": "333333333",
  "updates": [
    {
      "medication_name": "Paracétamol",
      "quantity_sold": 1
    },
    {
      "medication_name": "Amoxiciline",
      "quantity_sold": 2
    }
  ]
}
```

### 💊 Pharmacie – Voir son historique de vente
```http
GET /pharmacy/sales_history
```
  
---
  
## 👤 Patient 

### 👤 Patient – Connexion
```http
POST /login_patient
```

**Body**
```json
{
    "npi": "33333333",
    "password": "1234"
}
```
  
### 👤 Patient – Déconnexion
```http
POST /patient/logout_patient
```

### 👤 Patient – Voir son profil 
```http
GET /patient/me
```

### 👤 Patient – Voir ses ordonnances en cours de validité
```http
GET /patient/prescriptions
```

### 👤 Patient – Voir ses ordonnances archivées
```http
GET /patient/archived_prescriptions
```

### 👤 Patient – Transformer une ordonnace donnée en un code QR
```http
GET /patient/prescription/{prescription_id}/qrcode
```

---

## 🔐 Sécurité
- Les prescriptions sont signées par les médecins (Ed25519)
- Chaque mise à jour par une pharmacie est signée séparément
- Archivage automatique dès que tous les médicaments sont servis

---

## 📦 Déploiement

Peut être déployé sur :
- **Render**
- **Railway**
- **Fly.io**

Ajouter la clé Firebase (`serviceAccountKey.json`) en variable d’environnement ou fichier dans le déploiement.

---

## ✅ TODO

- [ ] Interface mobile des Patients, Médecins et Pharmacies avec Flutter
- [ ] Interface web pour Administrateurs

---

## 👤 Auteur

- Nom : Ariane AGBOTON

- Projet : Authentificateur d'ordonnance Médicales

- Encadrement : --

---

## 📄 Licence
MIT
