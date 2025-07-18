from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, List, Any
from datetime import datetime


# ------------- Utilisateurs (Patients) -------------
class UserRegister(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    city: str
    npi: str
    password: str
    role: List[str] = Field(default_factory=lambda: ["Patient"]) 
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class UserLogin(BaseModel):
    npi: str
    password: str

# ------------- Doctors -------------
class DoctorRegister(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    city: str
    npi: str
    password: str
    role: List[str] = Field(default_factory=lambda: ["Doctor"])
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())  

class DoctorLogin(BaseModel):
    npi: str
    password: str


# ------------- Pharmacy -------------
class PharmacyRegister(BaseModel):
    name: str
    email: EmailStr
    phone: str
    city: str
    serial_number: str
    password: str
    role: List[str] = Field(default_factory=lambda: ["Pharmacy"])
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())  

class PharmacyLogin(BaseModel):
    serial_number: str
    password: str

# ------------- Admin -------------
class AdminLogin(BaseModel):
    npi: str
    password: str
# ------------- Prescription -------------
class PrescriptionDetails(BaseModel):
    medication_name: str
    prescribed_quantity: int
    dosage: str
    frequency: str
    duration: str
    instructions: Optional[str] = None
    remaining_quantity: int = 0
    all_quantity_paid: bool = False

class CreatePrescription(BaseModel):
    patient_first_name: str
    patient_last_name: str
    patient_npi: str
    prescription_details: List[PrescriptionDetails]
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class MedicationUpdate(BaseModel):
    medication_name: str
    quantity_sold: int  # Quantité que le pharmacien a servie

class UpdatePrescriptionInput(BaseModel):
    prescription_id: str
    patient_npi: str
    updates: List[MedicationUpdate]


class QRScanInput(BaseModel):
    message: Dict[str, Any]       
    signature: str                
    public_key: str               