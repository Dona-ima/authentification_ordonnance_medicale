from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi import Body
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt
from models import UserRegister, UserLogin, DoctorLogin, DoctorRegister, PharmacyRegister, PharmacyLogin, CreatePrescription, QRScanInput,UpdatePrescriptionInput,AdminLogin
import os
import json
from typing import Dict, Any
import bcrypt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import base64
from dotenv import load_dotenv
import uuid
import qrcode
import io

from firebase import db


app = FastAPI(
    title="Prescription Authentication API", 
    version="1.0.0",
    description="API for managing prescription authentication and user registration in a healthcare system."
)

# Load environment variables
load_dotenv()  # charge les variables depuis .env

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

#------------------ Key section -------------------#
KEY_PATH = "private_key.pem"

def load_or_create_private_key():
    if os.path.exists(KEY_PATH):
        # Load the existing key
        with open(KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
    else:
        #  Créer une nouvelle clé et l'enregistrer
        private_key = Ed25519PrivateKey.generate()
        with open(KEY_PATH, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    return private_key

def get_public_key_pem(private_key):
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

private_key = load_or_create_private_key()
public_pem = get_public_key_pem(private_key)


# Clé privée pharmacie
PHARMACY_KEY_PATH = "pharmacy_private_key.pem"

def load_or_create_pharmacy_key():
    if os.path.exists(PHARMACY_KEY_PATH):
        with open(PHARMACY_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        with open(PHARMACY_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        return private_key

pharmacy_private_key = load_or_create_pharmacy_key()
pharmacy_public_key = pharmacy_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

#------------------ End -------------------#



#------------------ Functions section ------------------#
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        npi: str = payload.get("npi")
        role: str = payload.get("role")
        if npi is None or role is None:
            raise HTTPException(status_code=401, detail="Token invalide")
        return {"npi": npi, "role": role}
    except JWTError as e:
        print(f"JWT Error: {e}")
        raise HTTPException(status_code=401, detail="Token invalide")
    
def only_patient(current_user=Depends(get_current_user)):
    if "Patient" not in current_user["role"]:
        raise HTTPException(status_code=403, detail="Accès réservé aux patients")
    return current_user

def only_doctor(current_user=Depends(get_current_user)):
    if "Doctor" not in current_user["role"]:
        raise HTTPException(status_code=403, detail="Accès réservé aux docteurs")
    return current_user

def only_pharmacy(current_user=Depends(get_current_user)):
    if "Pharmacy" not in current_user["role"]:
        raise HTTPException(status_code=403, detail="Accès réservé aux pharmacies")
    return current_user

"""
def only_admin(current_user=Depends(get_current_user)):
    if "Admin" not in current_user["role"]:
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")
    return current_user
    
"""

def only_super_admin(current_user=Depends(get_current_user)):
    if "SuperAdmin" not in current_user["role"]:
        raise HTTPException(status_code=403, detail="Accès réservé au super admin")
    return current_user


def exclude_fields(data: dict, fields: list) -> dict:
    return {k: v for k, v in data.items() if k not in fields}

def include_fields(data: dict, fields: list) -> dict:
    return {k: data[k] for k in fields if k in data}

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def sign_message(message: Dict[str, Any], password: str) -> Dict[str, str]:
    """Signe un message avec la clé privée"""
    npi= message["doctor_npi"]
    # Vérifier le mot de passe du médecin depuis Firestore
    doctors_firestore = db.collection("doctors")
    query = doctors_firestore.where("npi", "==", npi).stream()
    doctor = next((doc.to_dict() for doc in query), None)
    if doctor and verify_password(password, doctor["password"]):
        message_json = json.dumps(message, sort_keys=True).encode("utf-8")
        signature = private_key.sign(message_json)
        signature_b64 = base64.b64encode(signature).decode()

        return {
            "message": message,
            "signature": signature_b64,
            "public_key": public_pem.decode()
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

def sign_pharmacy_log(data: dict) -> Dict[str, Any]:
    payload_json = json.dumps(data, sort_keys=True).encode("utf-8")
    signature = pharmacy_private_key.sign(payload_json)
    return {
        "signature": base64.b64encode(signature).decode(),
        "public_key": pharmacy_public_key
    }


#------------------ End -------------------#



@app.get("/landing_page")
async def get_landingPage():
    """Get landing page information for Lightning Vaccinal Book"""
    # This is a placeholder function. You can implement the logic to fetch or generate landing page
    return {
        "title": "Lightning Vaccinal Book",
        "description": "Manage your vaccination records and appointments easily.",
        "features": [
            "Create and manage vaccination records",
            "Schedule vaccination appointments",
            "View vaccination history",
            "Receive reminders for upcoming vaccinations"
        ],
        "contact": "For more information, contact us at"
    }


#------------------ Patient section -------------------#

@app.post("/login_patient")
async def login_user(data: UserLogin):
    patients_firestore = db.collection("patients")
    query = patients_firestore.where("npi", "==", data.npi).stream()

    patient = next((doc.to_dict() for doc in query), None)
    if not patient:
        raise HTTPException(status_code=404, detail="User not found")
    patient_data = patient

    if not verify_password(data.password, patient_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"npi": patient["npi"], "email": patient_data["email"], "role": patient_data["role"]}
    access_token = create_access_token(token_data)

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/patient/logout_patient", dependencies=[Depends(only_patient)])
async def logout_patient():
    return {"message": "Patient déconnecté avec succès."}


@app.get("/patient/me", dependencies=[Depends(only_patient)])
async def get_me_patient(current_user: dict = Depends(get_current_user)):
    patients_firestore = db.collection("patients")
    query = patients_firestore.where("npi", "==", current_user["npi"]).stream()

    patient = next((doc.to_dict() for doc in query), None)
    if not patient:
        raise HTTPException(status_code=404, detail="User not found")
    patient_data = exclude_fields(patient, ["password", "created_at"])  
    return patient_data

@app.get("/patient/prescriptions")
async def get_prescriptions_patient(user=Depends(only_patient)):
    users_firestore = db.collection("patients")
    query = users_firestore.document(user["npi"]).collection("prescriptions").stream()  
    prescriptions = [doc.to_dict() for doc in query]

    if not prescriptions:
        raise HTTPException(status_code=404, detail="No prescriptions found for this patient")

    # Garder uniquement le message (décodé du JSON string vers dictionnaire)
    filtered_prescriptions = []
    for p in prescriptions:
        if "message" in p:
            message = p["message"] if isinstance(p["message"], dict) else json.loads(p["message"])

            # Supprimer les médicaments déjà totalement servis
            all_details = message["prescription_details"]
            remaining_meds = [med for med in all_details if not med.get("all_quantity_paid", False)]
            paid_meds = [med for med in all_details if med.get("all_quantity_paid", False)]

            if not remaining_meds:
                continue  # ne pas afficher une ordonnance sans médicaments restants

            message["prescription_details"] = remaining_meds
            message["already_paid"] = paid_meds
           
            message.pop("doctor_npi", None)
            message.pop("created_at", None)
            filtered_prescriptions.append(message)


    return filtered_prescriptions

"""
@app.get("/patient/prescription/{prescription_id}")
async def get_prescription_by_id(prescription_id: str, user=Depends(only_patient)):
    doc = db.collection("patients").document(user["npi"]).collection("prescriptions").document(prescription_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Ordonnance non trouvée")
    return doc.to_dict()
"""

@app.get("/patient/archived_prescriptions", dependencies=[Depends(only_patient)])
async def get_archived_prescriptions(current_user=Depends(get_current_user)):
    patient_npi = current_user["npi"]
    archived_prescriptions_ref = db.collection("patients").document(patient_npi).collection("archived_prescriptions")
    archived_docs = archived_prescriptions_ref.stream()

    archived_list = []
    for doc in archived_docs:
        data = doc.to_dict()
        message = data.get("message")
        if message:
            # Si `message` est une chaîne JSON, tu peux la parser en dict pour plus de lisibilité (optionnel)
            try:
                import json
                message = json.loads(message)
            except Exception:
                pass
            archived_list.append(message)

    if not archived_list:
        raise HTTPException(status_code=404, detail="Aucune ordonnance archivée trouvée.")

    return {"archived_prescriptions": archived_list}




@app.get("/patient/prescription/{prescription_id}/qrcode")
async def generate_prescription_qrcode(prescription_id: str, user=Depends(only_patient)):
    doc = db.collection("patients").document(user["npi"]).collection("prescriptions").document(prescription_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Ordonnance non trouvée")

    prescription = doc.to_dict()

    if not all(k in prescription for k in ("message", "signature", "public_key")):
        raise HTTPException(status_code=400, detail="Ordonnance invalide pour génération QR code")

    qr_data = {
        "message": prescription["message"] if isinstance(prescription["message"], dict) else json.loads(prescription["message"]),
        "signature": prescription["signature"],
        "public_key": prescription["public_key"]
    }

    qr_data_json = json.dumps(qr_data, separators=(',', ':'))

    qr = qrcode.QRCode(
        version=1,
        box_size=3,   
        border=2     
    )
    qr.add_data(qr_data_json)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convertir en image PNG
    img_io = io.BytesIO()
    img.save(img_io, format='PNG')
    img_io.seek(0)

    return StreamingResponse(img_io, media_type="image/png")


#------------------ End -------------------#



#------------------ Doctor section -------------------#

@app.post("/login_doctor")
async def login_Dr(data: DoctorLogin):
    doctors_firestore = db.collection("doctors")
    query = doctors_firestore.where("npi", "==", data.npi).stream()

    doctor = next((doc.to_dict() for doc in query), None)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    doctor_data = doctor

    if not verify_password(data.password, doctor_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"npi": doctor["npi"], "email": doctor_data["email"], "role": doctor_data["role"]}
    access_token = create_access_token(token_data)

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/doctor/logout_doctor", dependencies=[Depends(only_doctor)])
async def logout_doctor():
    return {"message": "Docteur déconnecté avec succès."}

@app.get("/doctor/me", dependencies=[Depends(only_doctor)])
async def get_me_doctor(current_user: dict = Depends(get_current_user)): 
    doctors_firestore = db.collection("doctors")
    query = doctors_firestore.where("npi", "==", current_user["npi"]).stream()

    doctor = next((doc.to_dict() for doc in query), None)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    doctor_data = exclude_fields(doctor, ["password", "created_at"])  # Exclure le mot de passe et la date de création
    return doctor_data

@app.get("/doctor/prescriptions")
async def get_prescriptions_docteur(user=Depends(only_doctor)):
    doctors_firestore = db.collection("doctors")
    query = doctors_firestore.document(user["npi"]).collection("prescriptions").stream()

    prescriptions = [doc.to_dict() for doc in query]
    if not prescriptions:
        raise HTTPException(status_code=404, detail="No prescriptions found for this doctor")

    # Ne garder que le champ "message" (décodé en dict pour lisibilité)
    filtered_prescriptions = []
    for p in prescriptions:
        if "message" in p:
            message = p["message"] if isinstance(p["message"], dict) else json.loads(p["message"])
            # On filtre les champs qu’on ne veut pas renvoyer
            message.pop("doctor_npi", None)
            message.pop("id", None)
            message.pop("created_at", None)
            filtered_prescriptions.append(message)

    return filtered_prescriptions

"""
@app.get("/doctor/prescription/{prescription_id}")
async def get_prescription_by_id(prescription_id: str, user=Depends(only_doctor)):
    doc = db.collection("doctors").document(user["npi"]).collection("prescriptions").document(prescription_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Ordonnance non trouvée")
    return doc.to_dict()
"""

@app.post("/doctor/create_prescription", dependencies=[Depends(only_doctor)])
async def create_prescription(data: CreatePrescription, password: str = Body(...), current_user: dict = Depends(get_current_user)):
    doctors_firestore = db.collection("doctors")
    query = doctors_firestore.where("npi", "==", current_user["npi"]).stream()

    doctor = next((doc.to_dict() for doc in query), None)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    doctor_data = exclude_fields(doctor, ["password", "created_at"])
    prescription_id = str(uuid.uuid4())
    message = {
        "id": prescription_id,
        "patient_first_name": data.patient_first_name,
        "patient_last_name": data.patient_last_name,
        "patient_npi": data.patient_npi,
        "doctor_npi": doctor_data.get("npi"),
        "doctor_first_name": doctor_data.get("first_name"),
        "doctor_last_name": doctor_data.get("last_name"),
        "doctor_email": doctor_data.get("email"),
        "doctor_phone": doctor_data.get("phone"),
        "doctor_city": doctor_data.get("city"),
        "prescription_details": [
            {
                **med.dict(),
                "remaining_quantity": med.prescribed_quantity
            } for med in data.prescription_details
        ],
        "created_at": data.created_at
    }

    signed_message = sign_message(message, password)

    # Sauvegarde avec un ID personnalisé
    db.collection("doctors").document(doctor_data.get("npi")).collection("prescriptions").document(prescription_id).set(signed_message)
    db.collection("patients").document(data.patient_npi).collection("prescriptions").document(prescription_id).set(signed_message)

    return JSONResponse(content={"message": "Prescription signed and stored"}, status_code=201)

#------------------ End -------------------#

#------------------- Pharmacy section -------------------#

@app.post("/login_pharmacy")
async def login_pharmacy(data: PharmacyLogin):
    pharmacies = db.collection("pharmacies")
    query = pharmacies.where("serial_number", "==", data.serial_number).stream()
    pharmacy = next((doc.to_dict() for doc in query), None)

    if not pharmacy or not verify_password(data.password, pharmacy["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"npi": pharmacy["serial_number"], "email": pharmacy["email"], "role": pharmacy["role"]}
    access_token = create_access_token(token_data)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/pharmacy/logout_pharmacy")
async def logout_pharmacy():   
    return {"message": "Pharmacy déconnectée avec succès."}

@app.get("/pharmacy/me", dependencies=[Depends(only_pharmacy)])
async def get_me_pharmacy(current_user: dict = Depends(get_current_user)): 
    pharmacies = db.collection("pharmacies")
    query = pharmacies.where("serial_number", "==", current_user["npi"]).stream()
    pharmacy = next((doc.to_dict() for doc in query), None)

    if not pharmacy:
        raise HTTPException(status_code=404, detail="Pharmacy not found")

    pharmacy_data = exclude_fields(pharmacy, ["password", "created_at"])
    return pharmacy_data

from unicodedata import normalize

@app.post("/pharmacy/verify_prescription", dependencies=[Depends(only_pharmacy)])
async def verify_prescription_from_qr(qr_data: QRScanInput):
    try:
        # 1️⃣ Vérification de la signature du médecin
        message_json = json.dumps(qr_data.message, sort_keys=True).encode("utf-8")
        signature = base64.b64decode(qr_data.signature)
        cleaned_pem = normalize("NFKD", qr_data.public_key).replace("\u00a0", " ").encode()
        public_key = serialization.load_pem_public_key(cleaned_pem)
        public_key.verify(signature, message_json)

        # 2️⃣ Récupération des identifiants
        prescription_id = qr_data.message.get("id")
        patient_npi = qr_data.message.get("patient_npi")

        # 3️⃣ Lecture de la version à jour de l'ordonnance depuis Firestore
        doc_ref = db.collection("patients").document(patient_npi).collection("prescriptions").document(prescription_id)
        prescription_doc = doc_ref.get()
        if not prescription_doc.exists:
            raise HTTPException(status_code=404, detail="Ordonnance non trouvée dans la base de données")

        prescription_data = prescription_doc.to_dict()
        message_field = prescription_data["message"]

        if isinstance(message_field, str):
            # Si c'est une chaîne JSON, on la convertit en dict
            message_actuel = json.loads(message_field)
        elif isinstance(message_field, dict):
            # Si c'est déjà un dict, on l'utilise tel quel
            message_actuel = message_field
        else:
            raise HTTPException(status_code=400, detail="Format de message invalide dans la base de données.")

        # 4️⃣ Filtrer les médicaments non totalement servis
        prescription_details = [
            med for med in message_actuel.get("prescription_details", [])
            if not med.get("all_quantity_paid", False)
        ]

        if not prescription_details:
            raise HTTPException(status_code=400, detail="Tous les médicaments ont déjà été servis.")

        return {
            "message": "Ordonnance valide.",
            "prescription_id": prescription_id,
            "patient_npi": patient_npi,
            "prescription_details": prescription_details
        }

    except InvalidSignature:
        raise HTTPException(status_code=400, detail="Signature invalide.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ordonnance invalide : {str(e)}")




@app.post("/pharmacy/update_prescription", dependencies=[Depends(only_pharmacy)])
async def update_medication_status(data: UpdatePrescriptionInput, current_user=Depends(get_current_user)):
    doc_ref = db.collection("patients").document(data.patient_npi).collection("prescriptions").document(data.prescription_id)
    prescription_doc = doc_ref.get()

    if not prescription_doc.exists:
        raise HTTPException(status_code=404, detail="Ordonnance non trouvée")

    prescription = prescription_doc.to_dict()
    message = prescription["message"]
    if isinstance(message, str):
        message = json.loads(message)

    updated = False
    pharmacy_npi = current_user["npi"]

    # Mettre à jour les quantités et le statut de paiement
    for update in data.updates:
        for med in message["prescription_details"]:
            if med["medication_name"].lower() == update.medication_name.lower():
                initial_remaining = med.get("remaining_quantity", med["prescribed_quantity"])
                served_qty = update.quantity_sold

                if served_qty > initial_remaining:
                    raise HTTPException(status_code=400, detail=f"Trop servi pour {med['medication_name']}")

                med["remaining_quantity"] = initial_remaining - served_qty
                med["all_quantity_paid"] = (med["remaining_quantity"] == 0)
                updated = True

                # Historique des ventes
                db.collection("pharmacies") \
                  .document(pharmacy_npi) \
                  .collection("sales_history") \
                  .add({
                      "prescription_id": data.prescription_id,
                      "patient_npi": data.patient_npi,
                      "medication_name": med["medication_name"],
                      "quantity_served": served_qty,
                      "all_prescribed_quantity_paid": (med["remaining_quantity"] == 0),
                      "date": datetime.utcnow().isoformat()
                  })

    if not updated:
        raise HTTPException(status_code=400, detail="Aucun médicament mis à jour")

    # 🖊️ Créer le bloc de log signé de la pharmacie
    pharmacy_log_data = {
        "pharmacy_npi": pharmacy_npi,
        "signed_at": datetime.utcnow().isoformat(),
        "updates": [u.dict() for u in data.updates]
    }
    signed_log = sign_pharmacy_log(pharmacy_log_data)
    pharmacy_log_data.update(signed_log)

    # Ajouter le log signé à l'ordonnance
    existing_logs = prescription.get("pharmacy_logs", [])
    existing_logs.append(pharmacy_log_data)
    prescription["pharmacy_logs"] = existing_logs

    #Mettre à jour le message
    prescription["message"] = json.dumps(message, sort_keys=True)

    # Vérifier si tout a été payé → archiver
    all_paid = all(m.get("all_quantity_paid") is True for m in message["prescription_details"])

    if all_paid:
        archive_ref = db.collection("patients").document(data.patient_npi).collection("archived_prescriptions").document(data.prescription_id)
        archive_ref.set(prescription)
        doc_ref.delete()
        return {"message": "Tous les médicaments ont été payés. Ordonnance archivée avec signature."}

    # Sinon, juste mise à jour
    doc_ref.set(prescription)
    return {"message": "Bloc signé et médicaments mis à jour avec succès"}


from google.cloud import firestore
@app.get("/pharmacy/sales_history", dependencies=[Depends(only_pharmacy)])
async def get_sales_history(current_user=Depends(get_current_user)):
    pharmacy_npi = current_user["npi"]

    sales_ref = db.collection("pharmacies").document(pharmacy_npi).collection("sales_history")
    sales_docs = sales_ref.order_by("date", direction=firestore.Query.DESCENDING).stream()

    history = [doc.to_dict() for doc in sales_docs]

    if not history:
        raise HTTPException(status_code=404, detail="Aucune vente enregistrée")

    return {"history": history}



#------------------ End -------------------#



#------------------ Admin section -------------------#

@app.post("/login_admin")
async def login_admin(data: AdminLogin):
    patients_firestore = db.collection("patients")
    doctors_firestore = db.collection("doctors")

    query = patients_firestore.where("npi", "==", data.npi).stream()
    admin = next((doc.to_dict() for doc in query), None)

    if not admin:
        query = doctors_firestore.where("npi", "==", data.npi).stream()
        admin = next((doc.to_dict() for doc in query), None)

    if not admin:
        raise HTTPException(status_code=404, detail="User not found")

    admin_data = admin

    if "SuperAdmin" not in admin_data["role"]:  # À modifier si tu veux vérifier un rôle différent ( Admin ou SuperAdmin)
        raise HTTPException(status_code=403, detail="Access reserved for Admins")
    
    if not verify_password(data.password, admin_data["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"npi": admin["npi"], "email": admin_data["email"], "role": admin_data["role"]}
    access_token = create_access_token(token_data)

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/admin/logout_admin", dependencies=[Depends(only_super_admin)])
async def logout_admin():
    return {"message": "Admin déconnecté avec succès."}

@app.post("/admin/register_patient", dependencies=[Depends(only_super_admin)])
async def register_user(data: UserRegister):
    patients_firestore = db.collection("patients")
    query = patients_firestore.where("npi", "==", data.npi).stream()
    
    for doc in query:
        raise HTTPException(status_code=400, detail="Username already exists")

    data.password = hash_password(data.password)    
    patients_firestore.add(data.dict())

    return JSONResponse(content={"message": f"Patient {data.first_name} {data.last_name} registered successfully"}, status_code=201)

@app.get("/admin/patients", dependencies=[Depends(only_super_admin)])
async def get_all_users():
    patients = db.collection("patients").stream()
    return [include_fields(doc.to_dict(),["npi", "first_name", "last_name"]) for doc in patients]

@app.get("/admin/patients/{npi}", dependencies=[Depends(only_super_admin)])
async def get_patient_details(npi: str):
    patients_ref = db.collection("patients")
    query = patients_ref.where("npi", "==", npi).stream()
    patient = next((doc.to_dict() for doc in query), None)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    return exclude_fields(patient, ["password", "created_at"])

@app.get("/admin/patients/{npi}/prescriptions", dependencies=[Depends(only_super_admin)])
async def get_prescriptions_for_patient(npi: str):
    prescriptions_ref = db.collection("patients").document(npi).collection("prescriptions").stream()
    prescriptions = [
        exclude_fields(doc.to_dict(), ["signature", "public_key"])
        for doc in prescriptions_ref
    ]
    if not prescriptions:
        raise HTTPException(status_code=404, detail="No prescriptions found for this patient")
    return prescriptions

@app.get("/admin/patients/{npi}/archived_prescriptions", dependencies=[Depends(only_super_admin)])
async def get_archived_prescriptions_for_admin(npi: str):
    archived_ref = db.collection("patients").document(npi).collection("archived_prescriptions")
    archived_docs = archived_ref.stream()

    archived_prescriptions = []
    for doc in archived_docs:
        data = doc.to_dict()
        message = data.get("message")
        if isinstance(message, str):
            message = json.loads(message)
        
        archived_prescriptions.append({
            "message": message,
            "signature": data.get("signature"),
            "public_key": data.get("public_key")
        })

    if not archived_prescriptions:
        raise HTTPException(status_code=404, detail="Aucune ordonnance archivée trouvée.")

    return {"archived_prescriptions": archived_prescriptions}


@app.get("/admin/patients/{npi}/archived_prescriptions/{prescription_id}/logs", dependencies=[Depends(only_super_admin)])
async def get_pharmacy_logs_for_archived_prescription(npi: str, prescription_id: str):
    # 📄 Lire l'ordonnance archivée
    doc_ref = db.collection("patients").document(npi).collection("archived_prescriptions").document(prescription_id)
    doc = doc_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Ordonnance archivée non trouvée.")

    data = doc.to_dict()
    logs = data.get("pharmacy_logs", [])

    if not logs:
        raise HTTPException(status_code=404, detail="Aucun log de pharmacie trouvé pour cette ordonnance.")

    return {"pharmacy_logs": logs}



@app.delete("/admin/patients/{npi}/delete", dependencies=[Depends(only_super_admin)])
async def delete_patient(npi: str):
    patient_ref = db.collection("patients").document(npi)
    if not patient_ref.get().exists:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    # Supprimer les sous-collections (prescriptions)
    prescriptions_ref = patient_ref.collection("prescriptions").stream()
    for pres in prescriptions_ref:
        pres.reference.delete()

    patient_ref.delete()
    return {"message": f"Patient {npi} deleted successfully"}



@app.post("/admin/register_doctor", dependencies=[Depends(only_super_admin)])
async def register_doctor(data: DoctorRegister):
    doctors_firestore = db.collection("doctors")
    query = doctors_firestore.where("npi", "==", data.npi).stream()

    for doc in query:
        raise HTTPException(status_code=400, detail="Doctor ID already exists")

    data.password = hash_password(data.password)    
    doctors_firestore.add(data.dict())

    return JSONResponse(content={"message": f"Doctor {data.first_name} {data.last_name} registered successfully"}, status_code=201)


@app.get("/admin/doctors", dependencies=[Depends(only_super_admin)])
async def get_all_doctors():
    doctors = db.collection("doctors").stream()
    return [include_fields(doc.to_dict(),["npi", "first_name", "last_name"]) for doc in doctors]

@app.get("/admin/doctors/{npi}", dependencies= [Depends(only_super_admin)])
async def get_doctor_details(npi: str):
    doctors_ref = db.collection("doctors")
    query = doctors_ref.where("npi", "==", npi).stream()

    doctor = next((doc.to_dict() for doc in query), None)
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    return exclude_fields(doctor, ["password", "created_at"])

@app.get("/admin/doctors/{npi}/prescriptions", dependencies=[Depends(only_super_admin)])
async def get_prescriptions_for_doctor(npi: str):
    prescriptions_ref = db.collection("doctors").document(npi).collection("prescriptions").stream()
    prescriptions = [
        exclude_fields(doc.to_dict(), ["signature", "public_key"])
        for doc in prescriptions_ref
    ]
    if not prescriptions:
        raise HTTPException(status_code=404, detail="No prescriptions found for this doctor")
    return prescriptions

@app.delete("/admin/doctors/{npi}/delete", dependencies=[Depends(only_super_admin)])
async def delete_doctor(npi: str):
    doctor_ref = db.collection("doctors").document(npi)
    if not doctor_ref.get().exists:
        raise HTTPException(status_code=404, detail="Doctor not found")

    # Supprimer les sous-collections (prescriptions)
    prescriptions_ref = doctor_ref.collection("prescriptions").stream()
    for pres in prescriptions_ref:
        pres.reference.delete()

    doctor_ref.delete()
    return {"message": f"Doctor {npi} deleted successfully"}


@app.post("/admin/register_pharmacy", dependencies=[Depends(only_super_admin)])
async def register_pharmacy(data: PharmacyRegister):
    pharmacies = db.collection("pharmacies")
    query = pharmacies.where("serial_number", "==", data.serial_number).stream()

    if any(query):
        raise HTTPException(status_code=400, detail="Pharmacy already exists")

    data.password = hash_password(data.password)
    pharmacies.add(data.dict())
    return {"message": "Pharmacy registered successfully"}

@app.get("/admin/pharmacies", dependencies=[Depends(only_super_admin)])
async def get_all_pharmacies():
    pharmacies_ref = db.collection("pharmacies").stream()
    pharmacies = [
        {
            "name": doc.to_dict().get("name"),
            "serial_number": doc.to_dict().get("serial_number")  # ou doc.to_dict().get("serial_number") si stocké comme champ
        }
        for doc in pharmacies_ref
    ]

    if not pharmacies:
        raise HTTPException(status_code=404, detail="Aucune pharmacie trouvée.")

    return {"pharmacies": pharmacies}

@app.get("/admin/pharmacies/{serial_number}", dependencies=[Depends(only_super_admin)])
async def get_pharmacy_details(serial_number: str):
    query = db.collection("pharmacies").where("serial_number", "==", serial_number).stream()
    pharmacies = [doc.to_dict() for doc in query]
    if not pharmacies:
        raise HTTPException(status_code=404, detail="Pharmacie non trouvée.")
    # Normalement il ne devrait y avoir qu'une seule pharmacie par serial_number
    return {"pharmacy": pharmacies[0]}


@app.get("/admin/pharmacies/{serial_number}/sales_history", dependencies=[Depends(only_super_admin)])
async def get_pharmacy_sales_history(serial_number: str):
    sales_ref = db.collection("pharmacies").document(serial_number).collection("sales_history").stream()

    sales = [s.to_dict() for s in sales_ref]

    if not sales:
        raise HTTPException(status_code=404, detail="Aucune vente trouvée pour cette pharmacie.")

    return {"sales_history": sales}


@app.get("/admin/me", dependencies=[Depends(only_super_admin)])
async def get_me_admin(current_user: dict = Depends(get_current_user)): 
    """Get the current admin user"""
    patients_firestore = db.collection("patients")
    doctors_firestore = db.collection("doctors")

    query = patients_firestore.where("npi", "==", current_user["npi"]).stream()
    admin = next((doc.to_dict() for doc in query), None)

    if not admin:
        query = doctors_firestore.where("npi", "==", current_user["npi"]).stream()
        admin = next((doc.to_dict() for doc in query), None)

    if not admin:
        raise HTTPException(status_code=404, detail="User not found")

    admin_data = exclude_fields(admin, ["password", "created_at"])
    return admin_data

#------------------ End -------------------#

