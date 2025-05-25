# Local Development Guide (Backend & Frontend Locally, DB/Redis in Docker)

This guide helps you run the FastAPI full-stack template for development, with:
- Backend and frontend running locally (for hot reload and debugging)
- Database and Redis running in Docker
- Alembic migration instructions

---

## 1. Start Database and Redis in Docker

From your project root, run:

```bash
docker compose up -d postgres redis
```
- This starts the database and Redis containers (adjust service names if your `docker-compose.yml` uses different ones).

---

## 2. Run the Backend Locally

From the `backend/` directory:

1. **Install dependencies:**
   ```bash
   uv sync
   ```
2. **Activate the virtual environment:**
   ```bash
   source .venv/bin/activate
   ```
3. **Run the FastAPI app with hot reload:**
   ```bash
   fastapi run --reload app/main.py
   ```
   Or, if you use Uvicorn:
   ```bash
   uvicorn app.main:app --reload
   ```

**Note:**
- Ensure your `DATABASE_URL` in `backend/.env` points to the correct host.  
  - If backend runs locally and DB is in Docker, use `localhost` as the host.

---

## 3. Run the Frontend Locally

From the `frontend/` directory:

1. **Install dependencies:**
   ```bash
   npm install
   ```
2. **Start the frontend dev server:**
   ```bash
   npm run dev
   ```
   - The app will be available at [http://localhost:5173](http://localhost:5173).
3. **Configure API URL (if needed):**
   - In `frontend/.env`, set:
     ```
     VITE_API_URL=http://localhost:8000
     ```
   - This ensures the frontend talks to your local backend.

---

## 4. Running Database Migrations

### Apply Existing Migrations

From the `backend/` directory, with your virtualenv activated:
```bash
alembic upgrade head
```
- This applies all migrations to your database.

---

### Create a New Migration

1. **Make changes to your models** in `backend/app/models.py`.
2. **Generate a new migration:**
   ```bash
   alembic revision --autogenerate -m "Describe your change"
   ```
3. **Apply the migration:**
   ```bash
   alembic upgrade head
   ```

---

## 5. Quick Reference: Common Commands

```bash
# Start DB and Redis in Docker
docker compose up -d postgres redis

# Backend: install deps, activate venv, run with reload
cd backend
uv sync
source .venv/bin/activate
fastapi run --reload app/main.py

# Frontend: install deps, run dev server
cd frontend
npm install
npm run dev

# Run migrations
cd backend
source .venv/bin/activate
alembic upgrade head

# Create a new migration after model changes
alembic revision --autogenerate -m "Describe your change"
alembic upgrade head
```

---

## 6. Troubleshooting

- If backend cannot connect to the DB, check `DATABASE_URL` in `.env` (use `localhost` for local backend, `postgres` for Docker backend).
- If frontend cannot reach backend, check `VITE_API_URL` in `frontend/.env`.

---

Enjoy fast, modern local development!
