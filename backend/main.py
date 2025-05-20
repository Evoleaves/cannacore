
from fastapi import FastAPI
from auth import app as auth_app  # Reutilizamos la app del archivo auth.py

app = FastAPI(title="Cannacore API")

# Montamos la app de autenticación en la raíz
app.mount("/", auth_app)
@app.get("/")
def root():
    return {"message": "Cannacore API funcionando correctamente"}
