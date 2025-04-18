from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query, Path, Request
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Table, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import shutil
import os
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import List, Optional
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi import BackgroundTasks

app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "secret_key_for_testing_purposes")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255))
    name = Column(String(255), nullable=True)
    bio = Column(String(1024), nullable=True)
    avatar = Column(String(50), nullable=True)
    playlists = relationship("Playlist", back_populates="user", cascade="all, delete-orphan")

class Song(Base):
    __tablename__ = "songs"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String(255), nullable=False)
    artist = Column(String(255), nullable=False)
    duration = Column(Integer, nullable=False)
    category = Column(String(255), nullable=True)
    file_path = Column(String(512), nullable=False)
    upload_date = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    album = Column(String(255), nullable=True)

class Playlist(Base):
    __tablename__ = "playlists"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    user = relationship("User", back_populates="playlists")
    songs = relationship("Song", secondary="playlist_songs", backref="playlists")

playlist_songs = Table(
    'playlist_songs', Base.metadata,
    Column('playlist_id', Integer, ForeignKey('playlists.id', ondelete="CASCADE"), primary_key=True),
    Column('song_id', Integer, ForeignKey('songs.id', ondelete="CASCADE"), primary_key=True)
)

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class UserProfile(BaseModel):
    email: str
    name: Optional[str]
    bio: Optional[str]
    avatar: Optional[str]

    class Config:
        from_attributes = True  # Ensures correct ORM conversion

class SongBase(BaseModel):
    title: str
    artist: str
    duration: int
    category: Optional[str]
    album: Optional[str]

class SongCreate(SongBase):
    pass

class SongDisplay(SongBase):
    id: int
    upload_date: datetime
    class Config:
        from_attributes = True

class PlaylistBase(BaseModel):
    name: str

class PlaylistCreate(PlaylistBase):
    pass

class PlaylistDisplay(PlaylistBase):
    id: int
    songs: List[SongDisplay] = []
    class Config:
        from_attributes = True

# Auth setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Utility functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user


# Static files
os.makedirs("static/avatars", exist_ok=True)
os.makedirs("static/demo_songs", exist_ok=True)  # For preloaded songs
os.makedirs("uploads/songs", exist_ok=True)      # For user uploads
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# Routes
@app.post("/auth/register", status_code=201)
async def register(
    email: str = Form(...), 
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(password)
    user = User(email=email, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/auth/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": token, "token_type": "bearer"}

# Profile routes
@app.get("/profile", response_model=UserProfile)
async def get_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return current_user

@app.put("/profile/update", response_model=UserProfile)
async def update_profile(
    name: Optional[str] = Form(None),
    bio: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if name:
        current_user.name = name
    if bio:
        current_user.bio = bio
    db.commit()
    return current_user

@app.post("/profile/update-avatar")
async def update_avatar(
    avatar: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.avatar = avatar
    db.commit()
    return {"message": "Avatar updated successfully"}

@app.get("/avatars/list")
async def list_avatars():
    avatars = [f for f in os.listdir("static/avatars") 
               if f.endswith(('.png', '.jpg', '.jpeg'))]
    return {"avatars": avatars}

def save_file(file: UploadFile, file_location: str):
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

# Song routes
@app.post("/songs/upload", status_code=201)
async def upload_song(
    background_tasks: BackgroundTasks,
    title: str = Form(...),
    artist: str = Form(...),
    duration: int = Form(...),
    category: Optional[str] = Form(None),
    album: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    os.makedirs("uploads", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"{timestamp}_{file.filename}"
    file_location = f"uploads/songs/{filename}"

    # background_tasks.add_task(save_file, file, file_location)
    
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    new_song = Song(
        title=title,
        artist=artist,
        duration=duration,
        category=category,
        album=album,
        file_path=file_location,
        user_id=current_user.id
    )
    db.add(new_song)
    db.commit()
    return {"message": "Song uploaded successfully", "song_id": new_song.id}

@app.get("/songs/stream/{song_id}")
async def stream_song(
    song_id: int,
    db: Session = Depends(get_db)
):
    song = db.query(Song).filter(Song.id == song_id).first()
    if not song:
        raise HTTPException(status_code=404, detail="Song not found")
    
    if not os.path.exists(song.file_path):
        raise HTTPException(status_code=404, detail="Song file not found")
        
    return FileResponse(song.file_path, media_type="audio/mpeg")

@app.get("/songs/search", response_model=List[SongDisplay])
async def search_songs(
    query: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    sort_by: str = Query("upload_date"),
    db: Session = Depends(get_db)
):
    songs_query = db.query(Song)
    
    if query:
        songs_query = songs_query.filter(
            Song.title.ilike(f"%{query}%") | 
            Song.artist.ilike(f"%{query}%")
        )
    
    if category:
        songs_query = songs_query.filter(Song.category == category)
    
    if sort_by == "title":
        songs_query = songs_query.order_by(Song.title)
    elif sort_by == "artist":
        songs_query = songs_query.order_by(Song.artist)
    else:
        songs_query = songs_query.order_by(Song.upload_date.desc())
    
    return songs_query.all()

@app.get("/songs/categories", response_model=List[str])
async def get_categories(db: Session = Depends(get_db)):
    categories = db.query(Song.category).distinct().all()
    return [category[0] for category in categories if category[0]]

# Playlist routes
@app.post("/playlists/create", status_code=201)
async def create_playlist(
    name: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    playlist = Playlist(name=name, user_id=current_user.id)
    db.add(playlist)
    db.commit()
    return {"message": "Playlist created", "playlist_id": playlist.id}

@app.post("/playlists/add_song")
async def add_song_to_playlist(
    playlist_id: int = Form(...),
    song_id: int = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    playlist = db.query(Playlist).filter(
        Playlist.id == playlist_id,
        Playlist.user_id == current_user.id
    ).first()
    
    if not playlist:
        raise HTTPException(status_code=404, detail="Playlist not found")
    
    song = db.query(Song).filter(Song.id == song_id).first()
    if not song:
        raise HTTPException(status_code=404, detail="Song not found")
    
    if song in playlist.songs:
        return {"message": "Song already in playlist"}
    
    playlist.songs.append(song)
    db.commit()
    return {"message": "Song added to playlist"}

@app.delete("/playlists/remove_song")
async def remove_song_from_playlist(
    playlist_id: int = Form(...),
    song_id: int = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    playlist = db.query(Playlist).filter(
        Playlist.id == playlist_id,
        Playlist.user_id == current_user.id
    ).first()
    
    if not playlist:
        raise HTTPException(status_code=404, detail="Playlist not found")
    
    song = db.query(Song).filter(Song.id == song_id).first()
    if not song:
        raise HTTPException(status_code=404, detail="Song not found")
    
    if song not in playlist.songs:
        raise HTTPException(status_code=404, detail="Song not in playlist")
    
    playlist.songs.remove(song)
    db.commit()
    return {"message": "Song removed from playlist"}

@app.get("/playlists", response_model=List[PlaylistDisplay])
async def get_user_playlists(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(Playlist).filter(Playlist.user_id == current_user.id).all()

@app.get("/playlists/{playlist_id}", response_model=PlaylistDisplay)
async def get_playlist(
    playlist_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    playlist = db.query(Playlist).filter(
        Playlist.id == playlist_id,
        Playlist.user_id == current_user.id
    ).first()
    
    if not playlist:
        raise HTTPException(status_code=404, detail="Playlist not found")
    
    return playlist

@app.put("/playlists/{playlist_id}/reorder")
async def reorder_playlist(
    playlist_id: int,
    song_ids: List[int],
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    playlist = db.query(Playlist).filter(
        Playlist.id == playlist_id,
        Playlist.user_id == current_user.id
    ).first()
    
    if not playlist:
        raise HTTPException(status_code=404, detail="Playlist not found")
    
    playlist.songs = []
    db.commit()
    
    for song_id in song_ids:
        song = db.query(Song).filter(Song.id == song_id).first()
        if song:
            playlist.songs.append(song)
    
    db.commit()
    return {"message": "Playlist reordered successfully"}

# Library routes
@app.get("/user/uploads", response_model=List[SongDisplay])
async def get_user_uploads(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(Song).filter(Song.user_id == current_user.id).all()

@app.get("/user/artists", response_model=List[str])
async def get_user_artists(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    artists = db.query(Song.artist).filter(Song.user_id == current_user.id).distinct().all()
    return [artist[0] for artist in artists]

@app.get("/user/albums", response_model=List[str])
async def get_user_albums(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    albums = db.query(Song.album).filter(Song.user_id == current_user.id).distinct().all()
    return [album[0] for album in albums if album[0]]

# Create tables
Base.metadata.create_all(bind=engine)
# After Base.metadata.create_all(bind=engine)

def load_demo_songs(db: Session):
    if db.query(Song).count() > 0:  # Skip if DB already populated
        return
    
    demo_songs = [
  {"title": "positions", "artist": "Ariana Grande", "file": "positions.mp3"},
  {"title": "Senorita", "artist": "Camila Cabello, Shawn Mendes", "file": "Senorita.mp3"},
  {"title": "song2", "artist": "", "file": "song2.mp3"},
  {"title": "7 rings", "artist": "Ariana Grande", "file": "7 rings.mp3"},
  {"title": "10", "artist": "", "file": "10.mp3"},
  {"title": "11", "artist": "", "file": "11.mp3"},
  {"title": "Baby", "artist": "Justin Bieber", "file": "Baby.mp3"},
  {"title": "Blank Space", "artist": "Taylor Swift", "file": "Blank Space.mp3"},
  {"title": "build a bitch", "artist": "Bella Poarch", "file": "build a bitch.mp3"},
  {"title": "butter", "artist": "BTS", "file": "butter.mp3"},
  {"title": "cheap thrills", "artist": "Sia, Sean Paul", "file": "cheap thrills.mp3"},
  {"title": "chicken noodle soup", "artist": "J-Hope, Becky G", "file": "chicken noodle soup.mp3"},
  {"title": "Darasal", "artist": "Atif Aslam", "file": "Darasal.mp3"},
  {"title": "euphoria", "artist": "BTS", "file": "euphoria.mp3"},
  {"title": "hey mama", "artist": "David Guetta, Nicki Minaj", "file": "hey mama.mp3"},
  {"title": "I need somebody w", "artist": "", "file": "I need somebody w.mp3"},
  {"title": "Let Me Down Slowly", "artist": "Aftermorning", "file": "Let Me Down Slowly.mp3"},
  {"title": "levitating", "artist": "", "file": "levitating.mp3"},
  {"title": "life goes on", "artist": "BTS", "file": "life goes on.mp3"},
  {"title": "love nwantiti", "artist": "CKay", "file": "love nwantiti.mp3"},
  {"title": "money", "artist": "", "file": "money.mp3"},
  {"title": "peaches", "artist": "Justin Bieber, Daniel Caesar", "file": "peaches.mp3"},
  {"title": "Perfect", "artist": "Ed Sheeran", "file": "Perfect.mp3"},
  {"title": "permission to dance", "artist": "BTS", "file": "permission to dance.mp3"}
]

    for song in demo_songs:
        file_path = f"static/demo_songs/{song['file']}"
        if os.path.exists(file_path):
            db.add(Song(
                title=song["title"],
                artist=song["artist"],
                duration=song["duration"],
                file_path=file_path,
                user_id=None  # Mark as system-owned
            ))
    db.commit()

# Initialize demo data
with SessionLocal() as db:
    load_demo_songs(db)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


