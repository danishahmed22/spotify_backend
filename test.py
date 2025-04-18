# from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query, Path
# from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Table
# from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from datetime import datetime, timedelta
# import shutil
# import os
# from jose import JWTError, jwt
# from passlib.context import CryptContext
# from slowapi import Limiter
# from slowapi.util import get_remote_address
# from dotenv import load_dotenv
# from typing import List, Optional
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import FileResponse
# from pydantic import BaseModel
# from slowapi.errors import RateLimitExceeded
# from fastapi.exceptions import RequestValidationError
# from fastapi.responses import JSONResponse
# from fastapi import status
# from fastapi import FastAPI, Request
# from slowapi import Limiter, _rate_limit_exceeded_handler
# from slowapi.util import get_remote_address
# from fastapi.responses import JSONResponse
# from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Table, text

# app = FastAPI()
# limiter = Limiter(key_func=get_remote_address)
# app.state.limiter = limiter
# app.add_exception_handler(Exception, _rate_limit_exceeded_handler)

# # Load environment variables
# load_dotenv()
# DATABASE_URL = os.getenv("DATABASE_URL")
# SECRET_KEY = os.getenv("SECRET_KEY", "secret_key_for_testing_purposes")
# ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# limiter = Limiter(key_func=get_remote_address)
# app = FastAPI(title="Music Streaming API", description="API for managing music streaming with playlists and user profiles",version="1.0.0")

# # CORS Middleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Setup MySQL database
# engine = create_engine(
#     DATABASE_URL,
#     pool_pre_ping=True,
#     pool_recycle=3600,
#     pool_size=10,
#     max_overflow=20,
#     echo=False
# )
# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# Base = declarative_base()

# # Association table for many-to-many relationship between Playlists and Songs
# playlist_songs = Table(
#     'playlist_songs', Base.metadata,
#     Column('playlist_id', Integer, ForeignKey('playlists.id', ondelete="CASCADE"), primary_key=True),
#     Column('song_id', Integer, ForeignKey('songs.id', ondelete="CASCADE"), primary_key=True)
# )

# # Database Models with MySQL specific configurations
# class User(Base):
#     __tablename__ = "users"
#     id = Column(Integer, primary_key=True, index=True, autoincrement=True)
#     email = Column(String(255), unique=True, index=True)
#     hashed_password = Column(String(255))
#     name = Column(String(255), nullable=True)
#     bio = Column(String(1024), nullable=True)
#     profile_picture = Column(String(512), nullable=True)
#     playlists = relationship("Playlist", back_populates="user", cascade="all, delete-orphan")

# class Song(Base):
#     __tablename__ = "songs"
#     id = Column(Integer, primary_key=True, index=True, autoincrement=True)
#     title = Column(String(255), nullable=False)
#     artist = Column(String(255), nullable=False)
#     duration = Column(Integer, nullable=False)
#     category = Column(String(255), nullable=False)
#     file_path = Column(String(512), nullable=False)
#     upload_date = Column(DateTime, default=datetime.utcnow, server_default=text('CURRENT_TIMESTAMP'))

# class Playlist(Base):
#     __tablename__ = "playlists"
#     id = Column(Integer, primary_key=True, index=True, autoincrement=True)
#     name = Column(String(255), nullable=False)
#     user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
#     user = relationship("User", back_populates="playlists")
#     songs = relationship("Song", secondary=playlist_songs, backref="playlists")

# # Pydantic Models for API
# class SongBase(BaseModel):
#     title: str
#     artist: str
#     duration: int
#     category: str

# class SongDisplay(SongBase):
#     id: int
#     upload_date: datetime
    
#     class Config:
#         from_attributes = True

# class PlaylistBase(BaseModel):
#     name: str

# class PlaylistDisplay(PlaylistBase):
#     id: int
#     songs: List[SongDisplay] = []
    
#     class Config:
#         orm_mode = True

# class TokenData(BaseModel):
#     email: Optional[str] = None

# class Token(BaseModel):
#     access_token: str
#     token_type: str

# # Profile Management Models
# class UserProfileUpdate(BaseModel):
#     name: Optional[str] = None
#     bio: Optional[str] = None

# class PasswordChange(BaseModel):
#     current_password: str
#     new_password: str

# class UserProfileResponse(BaseModel):
#     email: str
#     name: Optional[str]
#     bio: Optional[str]
#     profile_picture: Optional[str]
    
#     class Config:
#         orm_mode = True

# # Dependency to get DB session
# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# # Authentication Helpers
# def get_password_hash(password):
#     return pwd_context.hash(password)

# def verify_password(plain_password, hashed_password):
#     return pwd_context.verify(plain_password, hashed_password)

# def create_access_token(data: dict, expires_delta: timedelta = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

# async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#         email: str = payload.get("sub")
#         if email is None:
#             raise credentials_exception
#         token_data = TokenData(email=email)
#     except JWTError:
#         raise credentials_exception
#     user = db.query(User).filter(User.email == token_data.email).first()
#     if user is None:
#         raise credentials_exception
#     return user

# # Exception handlers
# @app.exception_handler(RateLimitExceeded)
# async def rate_limit_handler(request, exc):
#     return JSONResponse(
#         status_code=status.HTTP_429_TOO_MANY_REQUESTS,
#         content={"detail": "Rate limit exceeded"}
#     )

# @app.exception_handler(RequestValidationError)
# async def validation_exception_handler(request, exc):
#     return JSONResponse(
#         status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
#         content={"detail": str(exc)}
#     )

# # User Routes
# @app.post("/auth/register", status_code=status.HTTP_201_CREATED)
# @limiter.limit("5/minute")
# async def register(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
#     existing_user = db.query(User).filter(User.email == email).first()
#     if existing_user:
#         raise HTTPException(status_code=400, detail="Email already registered")
    
#     hashed_password = get_password_hash(password)
#     user = User(email=email, hashed_password=hashed_password)
#     db.add(user)
#     db.commit()
#     return {"message": "User registered successfully"}

# @app.post("/auth/login", response_model=Token)
# @limiter.limit("10/minute")
# async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.email == form_data.username).first()
#     if not user or not verify_password(form_data.password, user.hashed_password):
#         raise HTTPException(status_code=401, detail="Invalid credentials")
    
#     access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     token = create_access_token(
#         data={"sub": user.email}, expires_delta=access_token_expires
#     )
#     return {"access_token": token, "token_type": "bearer"}

# # Profile Management Routes
# @app.get("/profile", response_model=UserProfileResponse)
# async def get_profile(
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     return current_user

# @app.put("/profile/update", response_model=UserProfileResponse)
# async def update_profile(
#     profile_data: UserProfileUpdate,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     if profile_data.name:
#         current_user.name = profile_data.name
#     if profile_data.bio:
#         current_user.bio = profile_data.bio
#     db.commit()
#     db.refresh(current_user)
#     return current_user

# @app.post("/profile/change-password")
# async def change_password(
#     password_data: PasswordChange,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     if not verify_password(password_data.current_password, current_user.hashed_password):
#         raise HTTPException(status_code=400, detail="Current password is incorrect")
    
#     current_user.hashed_password = get_password_hash(password_data.new_password)
#     db.commit()
#     return {"message": "Password updated successfully"}

# @app.post("/profile/upload-picture", response_model=UserProfileResponse)
# async def upload_profile_picture(
#     file: UploadFile = File(...),
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     os.makedirs("profile_pictures", exist_ok=True)
    
#     if current_user.profile_picture and os.path.exists(current_user.profile_picture):
#         os.remove(current_user.profile_picture)
    
#     file_extension = file.filename.split(".")[-1]
#     filename = f"profile_{current_user.id}.{file_extension}"
#     file_location = f"profile_pictures/{filename}"
    
#     with open(file_location, "wb") as buffer:
#         shutil.copyfileobj(file.file, buffer)
    
#     current_user.profile_picture = file_location
#     db.commit()
#     db.refresh(current_user)
#     return current_user

# @app.delete("/profile/delete-account")
# async def delete_account(
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     if current_user.profile_picture and os.path.exists(current_user.profile_picture):
#         os.remove(current_user.profile_picture)
    
#     playlists = db.query(Playlist).filter(Playlist.user_id == current_user.id).all()
#     for playlist in playlists:
#         db.delete(playlist)
    
#     db.delete(current_user)
#     db.commit()
#     return {"message": "Account deleted successfully"}

# # Song Management Routes
# @app.post("/songs/upload", status_code=status.HTTP_201_CREATED)
# @limiter.limit("10/minute")
# async def upload_song(
#     request: Request,
#     title: str = Form(...), 
#     artist: str = Form(...), 
#     duration: int = Form(...), 
#     category: str = Form(...),
#     file: UploadFile = File(...), 
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     os.makedirs("uploads", exist_ok=True)
    
#     timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
#     filename = f"{timestamp}_{file.filename}"
#     file_location = f"uploads/{filename}"
    
#     with open(file_location, "wb") as buffer:
#         shutil.copyfileobj(file.file, buffer)
    
#     new_song = Song(
#         title=title, 
#         artist=artist, 
#         duration=duration, 
#         category=category, 
#         file_path=file_location
#     )
#     db.add(new_song)
#     db.commit()
#     db.refresh(new_song)
    
#     return {"message": "Song uploaded successfully", "song_id": new_song.id}

# @app.get("/songs/stream/{song_id}")
# async def stream_song(
#     song_id: int = Path(..., description="The ID of the song to stream"),
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     song = db.query(Song).filter(Song.id == song_id).first()
#     if not song:
#         raise HTTPException(status_code=404, detail="Song not found")
    
#     if not os.path.exists(song.file_path):
#         raise HTTPException(status_code=404, detail="Song file not found")
        
#     return FileResponse(song.file_path, media_type="audio/mpeg")

# @app.get("/songs/search", response_model=List[SongDisplay])
# async def search_songs(
#     query: str = Query(None, description="Search by title or artist"),
#     category: str = Query(None, description="Filter by category"),
#     sort_by: str = Query("upload_date", description="Sort by: upload_date, title, artist"),
#     db: Session = Depends(get_db)
# ):
#     songs_query = db.query(Song)
    
#     if query:
#         songs_query = songs_query.filter(
#             Song.title.ilike(f"%{query}%") | 
#             Song.artist.ilike(f"%{query}%")
#         )
    
#     if category:
#         songs_query = songs_query.filter(Song.category == category)
    
#     if sort_by == "title":
#         songs_query = songs_query.order_by(Song.title)
#     elif sort_by == "artist":
#         songs_query = songs_query.order_by(Song.artist)
#     else:
#         songs_query = songs_query.order_by(Song.upload_date.desc())
    
#     return songs_query.all()

# # Playlist Management Routes
# @app.post("/playlists/create", status_code=status.HTTP_201_CREATED)
# async def create_playlist(
#     name: str = Form(...),
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     playlist = Playlist(name=name, user_id=current_user.id)
#     db.add(playlist)
#     db.commit()
#     db.refresh(playlist)
#     return {"message": "Playlist created", "playlist_id": playlist.id}

# @app.post("/playlists/add_song", status_code=status.HTTP_200_OK)
# async def add_song_to_playlist(
#     playlist_id: int = Form(...),
#     song_id: int = Form(...),
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     playlist = db.query(Playlist).filter(
#         Playlist.id == playlist_id,
#         Playlist.user_id == current_user.id
#     ).first()
    
#     if not playlist:
#         raise HTTPException(status_code=404, detail="Playlist not found or access denied")
    
#     song = db.query(Song).filter(Song.id == song_id).first()
#     if not song:
#         raise HTTPException(status_code=404, detail="Song not found")
    
#     if song in playlist.songs:
#         return {"message": "Song already in playlist"}
    
#     playlist.songs.append(song)
#     db.commit()
#     return {"message": "Song added to playlist"}

# @app.delete("/playlists/remove_song", status_code=status.HTTP_200_OK)
# async def remove_song_from_playlist(
#     playlist_id: int = Form(...),
#     song_id: int = Form(...),
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     playlist = db.query(Playlist).filter(
#         Playlist.id == playlist_id,
#         Playlist.user_id == current_user.id
#     ).first()
    
#     if not playlist:
#         raise HTTPException(status_code=404, detail="Playlist not found or access denied")
    
#     song = db.query(Song).filter(Song.id == song_id).first()
#     if not song:
#         raise HTTPException(status_code=404, detail="Song not found")
    
#     if song not in playlist.songs:
#         raise HTTPException(status_code=404, detail="Song not in playlist")
    
#     playlist.songs.remove(song)
#     db.commit()
#     return {"message": "Song removed from playlist"}

# @app.get("/playlists", response_model=List[PlaylistDisplay])
# async def get_user_playlists(
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     playlists = db.query(Playlist).filter(Playlist.user_id == current_user.id).all()
#     return playlists

# @app.get("/playlists/{playlist_id}", response_model=PlaylistDisplay)
# async def get_playlist(
#     playlist_id: int,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     playlist = db.query(Playlist).filter(
#         Playlist.id == playlist_id,
#         Playlist.user_id == current_user.id
#     ).first()
    
#     if not playlist:
#         raise HTTPException(status_code=404, detail="Playlist not found or access denied")
    
#     return playlist

# @app.delete("/playlists/{playlist_id}", status_code=status.HTTP_200_OK)
# async def delete_playlist(
#     playlist_id: int,
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     playlist = db.query(Playlist).filter(
#         Playlist.id == playlist_id,
#         Playlist.user_id == current_user.id
#     ).first()
    
#     if not playlist:
#         raise HTTPException(status_code=404, detail="Playlist not found or access denied")
    
#     db.delete(playlist)
#     db.commit()
#     return {"message": "Playlist deleted successfully"}


# # File upload directory
# UPLOAD_DIRECTORY = "uploads"
# os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

# # File Upload API
# @app.post("/files/upload", status_code=status.HTTP_201_CREATED)
# async def upload_file(file: UploadFile = File(...)):
#     file_path = os.path.join(UPLOAD_DIRECTORY, file.filename)
#     with open(file_path, "wb") as buffer:
#         shutil.copyfileobj(file.file, buffer)
#     return {"filename": file.filename, "message": "File uploaded successfully"}

# # File Streaming API
# @app.get("/files/stream/{filename}")
# async def stream_file(filename: str):
#     file_path = os.path.join(UPLOAD_DIRECTORY, filename)
#     if not os.path.exists(file_path):
#         raise HTTPException(status_code=404, detail="File not found")
#     return FileResponse(file_path, media_type="audio/mpeg")

# # File Download API
# @app.get("/files/download/{filename}")
# async def download_file(filename: str):
#     file_path = os.path.join(UPLOAD_DIRECTORY, filename)
#     if not os.path.exists(file_path):
#         raise HTTPException(status_code=404, detail="File not found")
#     return FileResponse(file_path, media_type="application/octet-stream", filename=filename)

# # Run DB migration
# Base.metadata.create_all(bind=engine)

# # Entry point for running the app
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)