from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.routes import scans, auth
from app.core.config import settings

# 1. Initialize the FastAPI Application instance
app = FastAPI(
    title="Phishing Detection & Mitigation API Engine",
    description="Production-grade core engine backend supplying heuristic and automated threat intelligence scans.",
    version="1.0.0"
)

# 2. Configure Cross-Origin Resource Sharing (CORS)
# This is crucial because it allows your Next.js web dashboard and React Native 
# mobile client to securely communicate with this backend API when deployed.
# Allowed origins are controlled via the CORS_ORIGINS env var (comma-separated).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],  # Allows GET, POST, OPTIONS, etc.
    allow_headers=["*"],
)

# 3. Include Application Route Modules
# This tells FastAPI to map all endpoints written inside your app/api/v1/routes/ files
app.include_router(scans.router)
app.include_router(auth.router)

# 4. Root Health Check Endpoint
@app.get("/", tags=["Health"])
def read_root():
    """
    Basic sanity check endpoint to verify that the containerized backend 
    service is online, accessible, and accepting traffic.
    """
    return {
        "status": "online", 
        "message": "Phishing detection engine core up and running smoothly."
    }