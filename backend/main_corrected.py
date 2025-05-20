
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from auth import authenticate_user, create_access_token, get_current_user, create_user
from PIL import Image
import numpy as np
import tensorflow as tf
import io
import uvicorn
import os

app = FastAPI()

# Configurar CORS (puede personalizarse)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Podés poner dominios específicos en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ruta raíz para verificar funcionamiento
@app.get("/")
def root():
    return {"message": "Cannacore API funcionando correctamente"}

# Modelo para registro
class UserRegister(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(user: UserRegister):
    result = create_user(user.username, user.password)
    if not result:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    return {"message": "Usuario creado correctamente"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales incorrectas")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/predict")
async def predict_image(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    contents = await file.read()
    image = Image.open(io.BytesIO(contents)).resize((224, 224))
    image_array = np.array(image) / 255.0
    image_array = np.expand_dims(image_array, axis=0)

    model = tf.keras.models.load_model("model.h5")
    prediction = model.predict(image_array)

    return {"prediction": prediction.tolist()}

# Ejecución para Railway
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
