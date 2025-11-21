import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone, date
from typing import Optional, List, Dict

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr

from database import db, create_document, get_documents

# ----------------------------
# Auth and Security Utilities
# ----------------------------
security = HTTPBearer(auto_error=False)
TOKENS: Dict[str, Dict] = {}
PASSWORD_SALT = os.getenv("PASSWORD_SALT", "assetmgr_salt_v1")


def hash_password(password: str) -> str:
    return hashlib.sha256((PASSWORD_SALT + password).encode()).hexdigest()


def create_token(user: Dict) -> str:
    token = secrets.token_urlsafe(32)
    TOKENS[token] = {
        "user_id": str(user.get("_id")),
        "email": user.get("email"),
        "role": user.get("role", "staff"),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(),
    }
    return token


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    payload = TOKENS.get(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    # Optionally check expiry
    try:
        if datetime.fromisoformat(payload["expires_at"]) < datetime.now(timezone.utc):
            TOKENS.pop(token, None)
            raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        pass
    # Fetch latest user data
    user = db["user"].find_one({"email": payload["email"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_role(required: List[str]):
    def _checker(user=Depends(get_current_user)):
        role = user.get("role", "staff")
        if role not in required:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return _checker


# ----------------------------
# Pydantic models (requests)
# ----------------------------
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = Field("staff", pattern="^(admin|manager|staff)$")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AssetCreateRequest(BaseModel):
    asset_id: str
    name: str
    type: str
    serial_number: Optional[str] = None
    purchase_date: Optional[date] = None
    supplier_name: Optional[str] = None
    warranty_period_months: Optional[int] = Field(None, ge=0)


class AssignmentCreateRequest(BaseModel):
    asset_id: str
    assignee_type: str
    assignee_name: str
    issue_date: date
    responsible_person: Optional[str] = None
    designation: Optional[str] = None
    notes: Optional[str] = None


class MaintenanceCreateRequest(BaseModel):
    asset_id: str
    service_date: date
    service_type: str = Field("scheduled")
    cost: Optional[float] = Field(None, ge=0)
    notes: Optional[str] = None
    next_service_date: Optional[date] = None


class ThresholdRequest(BaseModel):
    item_name: str
    current_level: int = Field(0, ge=0)
    min_level: int = Field(0, ge=0)
    unit: Optional[str] = "units"


class RequisitionRequest(BaseModel):
    item_name: str
    requested_by: str
    quantity: int = Field(..., ge=1)
    reason: Optional[str] = None


# ----------------------------
# FastAPI App
# ----------------------------
app = FastAPI(title="Asset Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files for uploads
UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


# ----------------------------
# Health/Test Endpoints
# ----------------------------
@app.get("/")
def root():
    return {"message": "Asset Management Backend Running"}


@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {
            "backend": "ok",
            "database": "ok",
            "collections": collections,
        }
    except Exception as e:
        return {"backend": "ok", "database": f"error: {str(e)}"}


# ----------------------------
# Auth Endpoints
# ----------------------------
@app.post("/auth/register")
def register(payload: RegisterRequest):
    # Only allow open registration if no admin exists
    admin_exists = db["user"].find_one({"role": "admin"})
    requester_role = "admin" if not admin_exists else None

    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "role": payload.role if requester_role == "admin" else (payload.role if not admin_exists else "staff"),
        "is_active": True,
        "hashed_password": hash_password(payload.password),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    db["user"].insert_one(user_doc)
    token = create_token(user_doc)
    return {"token": token, "role": user_doc["role"], "name": user_doc["name"], "email": user_doc["email"]}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("hashed_password") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token, "role": user.get("role", "staff"), "name": user.get("name"), "email": user.get("email")}


# ----------------------------
# Assets
# ----------------------------
@app.post("/assets")
def create_asset(payload: AssetCreateRequest, user=Depends(require_role(["admin", "manager"]))):
    # Ensure unique asset_id
    if db["asset"].find_one({"asset_id": payload.asset_id}):
        raise HTTPException(status_code=400, detail="Asset ID already exists")
    asset = payload.model_dump()
    asset.update({
        "status": "available",
        "documents": [],
        "created_by": user.get("email"),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    db["asset"].insert_one(asset)
    return {"message": "Asset created", "asset": asset}


@app.get("/assets")
def list_assets(q: Optional[str] = None):
    query = {}
    if q:
        query = {"$or": [
            {"asset_id": {"$regex": q, "$options": "i"}},
            {"name": {"$regex": q, "$options": "i"}},
            {"type": {"$regex": q, "$options": "i"}},
        ]}
    items = list(db["asset"].find(query, {"_id": 0}))
    return {"items": items}


@app.get("/assets/{asset_id}")
def get_asset(asset_id: str):
    asset = db["asset"].find_one({"asset_id": asset_id}, {"_id": 0})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@app.post("/assets/{asset_id}/documents")
def upload_asset_document(
    asset_id: str,
    category: Optional[str] = Form("other"),
    file: UploadFile = File(...),
    user=Depends(require_role(["admin", "manager"]))
):
    asset = db["asset"].find_one({"asset_id": asset_id})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Save file to uploads directory
    safe_name = f"{asset_id}_{int(datetime.now().timestamp())}_{file.filename}"
    dest_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(dest_path, "wb") as f:
        f.write(file.file.read())

    doc = {
        "filename": file.filename,
        "url": f"/uploads/{safe_name}",
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "category": category or "other",
    }
    db["asset"].update_one({"asset_id": asset_id}, {"$push": {"documents": doc}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    return {"message": "Uploaded", "document": doc}


# ----------------------------
# Assignments
# ----------------------------
@app.post("/assignments")
def create_assignment(payload: AssignmentCreateRequest, user=Depends(require_role(["admin", "manager"]))):
    asset = db["asset"].find_one({"asset_id": payload.asset_id})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Deactivate any active assignment for this asset (reallocation)
    db["assignment"].update_many({"asset_id": payload.asset_id, "active": True}, {"$set": {"active": False}})

    assignment = payload.model_dump()
    assignment.update({
        "active": True,
        "created_by": user.get("email"),
        "created_at": datetime.now(timezone.utc)
    })
    db["assignment"].insert_one(assignment)

    # Update asset status
    db["asset"].update_one({"asset_id": payload.asset_id}, {"$set": {"status": "assigned", "updated_at": datetime.now(timezone.utc)}})

    return {"message": "Asset assigned", "assignment": assignment}


@app.post("/assignments/{asset_id}/return")
def return_asset(asset_id: str, user=Depends(require_role(["admin", "manager"]))):
    updated = db["assignment"].update_many({"asset_id": asset_id, "active": True}, {"$set": {"active": False}})
    if updated.modified_count == 0:
        raise HTTPException(status_code=404, detail="No active assignment found")
    db["asset"].update_one({"asset_id": asset_id}, {"$set": {"status": "available", "updated_at": datetime.now(timezone.utc)}})
    return {"message": "Asset returned"}


@app.get("/assignments")
def list_assignments(asset_id: Optional[str] = None, active: Optional[bool] = None):
    query: Dict = {}
    if asset_id:
        query["asset_id"] = asset_id
    if active is not None:
        query["active"] = active
    items = list(db["assignment"].find(query, {"_id": 0}))
    return {"items": items}


# ----------------------------
# Maintenance
# ----------------------------
@app.post("/maintenance")
def add_maintenance(payload: MaintenanceCreateRequest, user=Depends(require_role(["admin", "manager"]))):
    asset = db["asset"].find_one({"asset_id": payload.asset_id})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    record = payload.model_dump()
    record.update({
        "created_by": user.get("email"),
        "created_at": datetime.now(timezone.utc)
    })
    db["maintenance"].insert_one(record)

    # Optionally mark asset in maintenance on service date
    db["asset"].update_one({"asset_id": payload.asset_id}, {"$set": {"status": "maintenance", "updated_at": datetime.now(timezone.utc)}})

    return {"message": "Maintenance recorded", "record": record}


@app.get("/maintenance")
def list_maintenance(asset_id: Optional[str] = None):
    query: Dict = {}
    if asset_id:
        query["asset_id"] = asset_id
    items = list(db["maintenance"].find(query, {"_id": 0}))
    return {"items": items}


@app.get("/maintenance/reminders")
def maintenance_reminders(days: int = 30):
    today = date.today()
    upcoming = today + timedelta(days=days)
    items = list(db["maintenance"].find({
        "next_service_date": {"$gte": today.isoformat(), "$lte": upcoming.isoformat()}
    }, {"_id": 0}))
    return {"items": items}


# ----------------------------
# Inventory thresholds and requisitions
# ----------------------------
@app.post("/inventory-thresholds")
def upsert_threshold(payload: ThresholdRequest, user=Depends(require_role(["admin", "manager"]))):
    db["inventorythreshold"].update_one(
        {"item_name": payload.item_name},
        {"$set": payload.model_dump()},
        upsert=True,
    )
    return {"message": "Threshold saved"}


@app.get("/alerts/low-inventory")
def low_inventory_alerts():
    items = list(db["inventorythreshold"].find({"$expr": {"$lt": ["$current_level", "$min_level"]}}, {"_id": 0}))
    return {"items": items}


@app.post("/requisitions")
def create_requisition(payload: RequisitionRequest, user=Depends(require_role(["admin", "manager", "staff"]))):
    doc = payload.model_dump()
    doc.update({
        "status": "open",
        "requested_at": datetime.now(timezone.utc),
        "requested_by_user": user.get("email"),
    })
    db["requisition"].insert_one(doc)
    return {"message": "Requisition created", "requisition": doc}


@app.get("/requisitions")
def list_requisitions(status: Optional[str] = None):
    query: Dict = {}
    if status:
        query["status"] = status
    items = list(db["requisition"].find(query, {"_id": 0}))
    return {"items": items}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
