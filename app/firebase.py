# Import necessary libraries for Firestore
import firebase_admin
from firebase_admin import credentials, firestore
from models import UserLogin, UserRegister, DoctorLogin, DoctorRegister, CreatePrescription

# Initialize Firebase Admin SDK
# Make sure to replace "firebase_key.json" with the path to your Firebase service account key
cred = credentials.Certificate("firebase_key.json")  # Chemin vers ton fichier
firebase_admin.initialize_app(cred)
db = firestore.client()  