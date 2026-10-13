from dotenv import load_dotenv
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import re
import uuid
import bcrypt
import jwt
import logging
import requests
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field

# ------------------------- Setup -------------------------
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALGO = "HS256"
JWT_EXPIRY_DAYS = 7
ADMIN_CODE = os.environ['ADMIN_VALIDATION_CODE']

# --- Emergent Object Storage ---
APP_NAME = "optik-event"
UPLOADS_DIR = ROOT_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
STORAGE_BASE = (os.environ.get("INTEGRATION_PROXY_URL") or "").strip() or "https://integrations.emergentagent.com"
STORAGE_URL = STORAGE_BASE.rstrip("/") + "/objstore/api/v1/storage"
EMERGENT_KEY = os.environ.get("EMERGENT_LLM_KEY")
_storage_key: Optional[str] = None

logger = logging.getLogger("optik")
logging.basicConfig(level=logging.INFO)

def init_storage(force: bool = False) -> str:
    global _storage_key
    if _storage_key and not force:
        return _storage_key
    resp = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_KEY}, timeout=30)
    resp.raise_for_status()
    _storage_key = resp.json()["storage_key"]
    return _storage_key

def put_object(path: str, data: bytes, content_type: str) -> dict:
    key = init_storage()
    resp = requests.put(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key, "Content-Type": content_type},
        data=data, timeout=120,
    )
    if resp.status_code == 404:
        # stale key — re-init and retry once
        key = init_storage(force=True)
        resp = requests.put(
            f"{STORAGE_URL}/objects/{path}",
            headers={"X-Storage-Key": key, "Content-Type": content_type},
            data=data, timeout=120,
        )
    resp.raise_for_status()
    return resp.json()

def get_object(path: str) -> tuple[bytes, str]:
    key = init_storage()
    resp = requests.get(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key}, timeout=60,
    )
    if resp.status_code == 404 and _storage_key:
        key = init_storage(force=True)
        resp = requests.get(
            f"{STORAGE_URL}/objects/{path}",
            headers={"X-Storage-Key": key}, timeout=60,
        )
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "application/octet-stream")

app = FastAPI(title="Optik Event API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

# ------------------------- Constants -------------------------
PHOTO_CATEGORIES = ["mariage", "bapteme", "anniversaire", "gala", "corporate", "autre"]
DECOR_CATEGORIES = ["arche_florale", "table_honneur", "eclairage", "decor_scenique", "autre"]
IMPRIMERIE_CATEGORIES = ["flyer", "carte_visite", "invitation", "banniere", "affiche", "menu", "autre"]
OPTIC_TYPES = ["photo", "decor", "imprimerie"]
CATS_BY_OPTIC = {"photo": PHOTO_CATEGORIES, "decor": DECOR_CATEGORIES, "imprimerie": IMPRIMERIE_CATEGORIES}
MIME_BY_EXT = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".gif": "image/gif"}

# ------------------------- Auth helpers -------------------------
def hash_password(pwd: str) -> str:
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

def verify_password(pwd: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pwd.encode(), hashed.encode())
    except Exception:
        return False

def create_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRY_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

async def get_current_admin(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="Authentification requise")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expirée")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    user.pop("_id", None)
    user.pop("password_hash", None)
    return user

# ------------------------- Models -------------------------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    validation_code: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class AuthOut(BaseModel):
    token: str
    user: dict

class MediaItem(BaseModel):
    id: str
    optic_type: str
    category: str
    title: str
    description: str = ""
    location: str = ""
    event_date: str = ""
    media_kind: str
    image_url: str = ""
    youtube_url: str = ""
    featured: bool = False
    created_at: str

class MediaUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None
    event_date: Optional[str] = None
    category: Optional[str] = None
    optic_type: Optional[str] = None
    featured: Optional[bool] = None
    youtube_url: Optional[str] = None

# ------------------------- Auth routes -------------------------
@api_router.post("/auth/register", response_model=AuthOut)
async def register(data: RegisterIn):
    if data.validation_code != ADMIN_CODE:
        raise HTTPException(status_code=403, detail="Code de validation invalide")
    email = data.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Cet email est déjà enregistré")
    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": email,
        "password_hash": hash_password(data.password),
        "role": "admin",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(doc)
    token = create_token(user_id, email)
    return AuthOut(token=token, user={"id": user_id, "email": email, "role": "admin"})

@api_router.post("/auth/login", response_model=AuthOut)
async def login(data: LoginIn):
    email = data.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    token = create_token(user["id"], email)
    return AuthOut(token=token, user={"id": user["id"], "email": email, "role": user.get("role", "admin")})

@api_router.get("/auth/me")
async def me(current=Depends(get_current_admin)):
    return current

# ------------------------- Media routes -------------------------
def _serialize(doc: dict) -> dict:
    doc.pop("_id", None)
    return doc

@api_router.get("/media", response_model=List[MediaItem])
async def list_media(optic_type: Optional[str] = None, category: Optional[str] = None):
    query = {"is_deleted": {"$ne": True}}
    if optic_type:
        if optic_type not in OPTIC_TYPES:
            raise HTTPException(status_code=400, detail="Type invalide")
        query["optic_type"] = optic_type
    if category:
        query["category"] = category
    docs = await db.media.find(query).sort("created_at", -1).to_list(500)
    return [_serialize(d) for d in docs]

@api_router.get("/media/categories")
async def categories():
    return {"photo": PHOTO_CATEGORIES, "decor": DECOR_CATEGORIES, "imprimerie": IMPRIMERIE_CATEGORIES}

@api_router.get("/media/{item_id}", response_model=MediaItem)
async def get_media(item_id: str):
    doc = await db.media.find_one({"id": item_id, "is_deleted": {"$ne": True}})
    if not doc:
        raise HTTPException(status_code=404, detail="Non trouvé")
    return _serialize(doc)

@api_router.post("/media/upload", response_model=MediaItem)
async def upload_photo(
    file: UploadFile = File(...),
    optic_type: str = Form(...),
    category: str = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    location: str = Form(""),
    event_date: str = Form(""),
    featured: bool = Form(False),
    current=Depends(get_current_admin),
):
    if optic_type not in OPTIC_TYPES:
        raise HTTPException(status_code=400, detail="Type invalide")
    valid_cats = CATS_BY_OPTIC[optic_type]
    if category not in valid_cats:
        raise HTTPException(status_code=400, detail="Catégorie invalide")

    ext = Path(file.filename or "").suffix.lower() or ".jpg"
    if ext not in MIME_BY_EXT:
        raise HTTPException(status_code=400, detail="Format image non supporté")

    content_type = MIME_BY_EXT[ext]
    filename = f"{uuid.uuid4().hex}{ext}"
    storage_path = filename
    data = await file.read()
    try:
        (UPLOADS_DIR / filename).write_bytes(data)
    except Exception as e:
        logger.exception("Local storage write failed")
        raise HTTPException(status_code=500, detail=f"Erreur d'enregistrement: {e}")

    item_id = str(uuid.uuid4())
    doc = {
        "id": item_id,
        "optic_type": optic_type,
        "category": category,
        "title": title,
        "description": description,
        "location": location,
        "event_date": event_date,
        "media_kind": "image",
        "storage_path": storage_path,
        "content_type": content_type,
        "image_url": f"/api/files/{storage_path}",
        "youtube_url": "",
        "featured": bool(featured),
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.media.insert_one(doc)
    return _serialize(doc)

def extract_youtube_id(url: str) -> Optional[str]:
    if not url:
        return None
    patterns = [
        r"(?:youtube\.com/watch\?v=)([\w-]{11})",
        r"(?:youtu\.be/)([\w-]{11})",
        r"(?:youtube\.com/embed/)([\w-]{11})",
        r"(?:youtube\.com/shorts/)([\w-]{11})",
    ]
    for p in patterns:
        m = re.search(p, url)
        if m:
            return m.group(1)
    return None

class VideoIn(BaseModel):
    optic_type: str
    category: str
    title: str
    description: str = ""
    location: str = ""
    event_date: str = ""
    youtube_url: str
    featured: bool = False

@api_router.post("/media/video", response_model=MediaItem)
async def add_video(data: VideoIn, current=Depends(get_current_admin)):
    if data.optic_type not in OPTIC_TYPES:
        raise HTTPException(status_code=400, detail="Type invalide")
    valid_cats = CATS_BY_OPTIC[data.optic_type]
    if data.category not in valid_cats:
        raise HTTPException(status_code=400, detail="Catégorie invalide")
    yid = extract_youtube_id(data.youtube_url)
    if not yid:
        raise HTTPException(status_code=400, detail="URL YouTube invalide")

    item_id = str(uuid.uuid4())
    thumb = f"https://img.youtube.com/vi/{yid}/hqdefault.jpg"
    doc = {
        "id": item_id,
        "optic_type": data.optic_type,
        "category": data.category,
        "title": data.title,
        "description": data.description,
        "location": data.location,
        "event_date": data.event_date,
        "media_kind": "video",
        "image_url": thumb,
        "youtube_url": f"https://www.youtube.com/embed/{yid}",
        "featured": bool(data.featured),
        "is_deleted": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.media.insert_one(doc)
    return _serialize(doc)

@api_router.patch("/media/{item_id}", response_model=MediaItem)
async def update_media(item_id: str, data: MediaUpdate, current=Depends(get_current_admin)):
    update = {k: v for k, v in data.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(status_code=400, detail="Aucune modification")
    if "youtube_url" in update:
        yid = extract_youtube_id(update["youtube_url"])
        if yid:
            update["youtube_url"] = f"https://www.youtube.com/embed/{yid}"
            update["image_url"] = f"https://img.youtube.com/vi/{yid}/hqdefault.jpg"
    result = await db.media.find_one_and_update(
        {"id": item_id}, {"$set": update}, return_document=True
    )
    if not result:
        raise HTTPException(status_code=404, detail="Non trouvé")
    return _serialize(result)

@api_router.delete("/media/{item_id}")
async def delete_media(item_id: str, current=Depends(get_current_admin)):
    doc = await db.media.find_one({"id": item_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Non trouvé")
    # Soft-delete (object storage has no delete API)
    await db.media.update_one({"id": item_id}, {"$set": {"is_deleted": True}})
    return {"ok": True}

# Public file streaming — gallery images are meant to be public
@api_router.get("/files/{path:path}")
async def serve_file(path: str):
    doc = await db.media.find_one({"storage_path": path, "is_deleted": {"$ne": True}})
    if not doc:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    local_file = UPLOADS_DIR / Path(path).name
    if Path(path).name == path and local_file.is_file():
        return Response(
            content=local_file.read_bytes(),
            media_type=doc.get("content_type") or "application/octet-stream",
            headers={"Cache-Control": "public, max-age=86400"},
        )
    try:
        data, content_type = get_object(path)
    except Exception:
        raise HTTPException(status_code=404, detail="Fichier introuvable")
    return Response(
        content=data,
        media_type=doc.get("content_type") or content_type,
        headers={"Cache-Control": "public, max-age=86400"},
    )

@api_router.get("/")
async def root():
    return {"app": "Optik Event API", "status": "ok"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.media.create_index("optic_type")
    await db.media.create_index("category")
    await db.media.create_index("storage_path")
    try:
        init_storage()
        logger.info("Object storage initialized")
    except Exception as e:
        logger.error(f"Storage init failed at startup: {e}")

@app.on_event("shutdown")
async def shutdown():
    client.close()
