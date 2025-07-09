from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
from evasion import fingerprint_advanced

import logging
from datetime import datetime

# === Configuración del Servidor ===
app = FastAPI(
    title="GhostFPrint API",
    description="Scanner cuántico para fingerprinting multidimensional de sitios web.",
    version="2.0.0 🌠",
)



# === Middleware universal para CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Puedes restringir en producción
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Ruta de bienvenida cósmica ===
@app.get("/", response_class=HTMLResponse)
async def index():
    """
    🌟 Página principal que entrega la interfaz HTML.
    """
    try:
        with open("frontend.html", "r", encoding="utf-8") as f:
            html = f.read()
        return HTMLResponse(content=html)
    except Exception as e:
        logging.error(f"Error cargando frontend: {e}")
        return HTMLResponse(
            content=f"<h1>Error cargando frontend</h1><p>{e}</p>",
            status_code=500
        )

# === Ruta de escaneo cuántico ===
@app.post("/scan")
async def scan(request: Request):
    """
    🚀 Recibe una URL y ejecuta fingerprinting multidimensional.
    """
    try:
        data = await request.json()
        url = data.get("url", "").strip()

        # === Validaciones básicas ===
        if not url:
            return JSONResponse(
                content={"error": "La URL está vacía o no fue proporcionada."},
                status_code=400
            )

        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)

        if parsed.scheme not in ("http", "https"):
            return JSONResponse(
                content={"error": "Esquema no válido. Usa http o https."},
                status_code=400
            )

        if not parsed.netloc:
            return JSONResponse(
                content={"error": "Dominio inválido. Asegúrate de que sea válido."},
                status_code=400
            )

        logging.info(f"🌐 Escaneando URL: {parsed.geturl()}")

        # === Ejecutar fingerprint avanzado ===
        result = await fingerprint_advanced(parsed.geturl())

        logging.info(f"✅ Scan completado: {parsed.geturl()}")
        return JSONResponse(content=result, status_code=200)

    except Exception as e:
        logging.exception("💥 Error durante el escaneo")
        return JSONResponse(
            content={"error": f"Error interno del servidor: {str(e)}"},
            status_code=500
        )
