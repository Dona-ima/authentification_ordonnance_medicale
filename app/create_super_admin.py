import os
from firebase import db
from dotenv import load_dotenv
import bcrypt
from datetime import datetime

# Charger les variables d'environnement
load_dotenv()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def create_super_admin():
    first_name = input("Prénom du super admin : ").strip()
    last_name = input("Nom du super admin : ").strip()
    email = input("Email du super admin : ").strip()
    password = input("Mot de passe : ").strip()
    npi = input("NPI (identifiant unique) : ").strip()
    city = input("Ville : ").strip()
    phone = input("Téléphone : ").strip()

    patients_firestore = db.collection("patients")
    
    # Vérifie s'il existe déjà un utilisateur avec cet email
    existing = patients_firestore.where("email", "==", email).stream()
    for doc in existing:
        print("⚠️ Un utilisateur avec cet email existe déjà.")
        return

    user_data = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "phone": phone,
        "city": city,
        "npi": npi,
        "password": hash_password(password),
        "role": ["SuperAdmin", "Patient"],
        "created_at": datetime.utcnow().isoformat()
    }
    patients_firestore.add(user_data)
    print("✅ Super admin créé avec succès.")

if __name__ == "__main__":
    create_super_admin()