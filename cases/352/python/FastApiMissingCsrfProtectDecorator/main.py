"""Application entrypoint: FastAPI app with starlette-wtf CSRF protection."""

from fastapi import FastAPI
from starlette_wtf import CSRFProtectMiddleware

from account import router as account_router
from config import settings

app = FastAPI(title="Acme Account Service")

# Registers the middleware that generates and stores the per-session CSRF
# token. FastAPI has no framework-native CSRF protection of its own, and
# this middleware alone does not enforce anything - each state-changing
# route still needs its own @csrf_protect decorator to actually validate
# the token on submit.
app.add_middleware(CSRFProtectMiddleware, csrf_secret=settings.CSRF_SECRET)

app.include_router(account_router)
