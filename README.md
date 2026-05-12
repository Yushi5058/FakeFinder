# FakeFinder

A Django-based email scanner that analyzes `.eml` files to detect phishing and fake emails using a trained ML model and header analysis.

## Features

- Upload and scan `.eml` email files via a web interface
- ML-powered phishing detection (Random Forest with TF-IDF + structural features)
- Risk scoring: `LOW` (safe), `MEDIUM` (review), `HIGH` (phishing)
- Suspicious URL extraction with sanitization
- Sender domain analysis and header anomaly detection
- User authentication (register/login/logout)
- Scan history and report management per user
- Rate-limiting on login attempts
- Security hardening in production (HSTS, secure cookies, CSRF protection)

## Architecture

```
FakeFinder/
├── src/                 # Django project root (manage.py)
│   ├── FakeFinder/      # Django project settings
│   ├── scanner/         # Main app: models, views, utils
│   │   ├── models.py    # ScanReport model
│   │   ├── views.py     # Upload, report, auth views
│   │   ├── utils.py     # .eml parsing and URL extraction
│   │   └── urls.py      # URL routing
│   └── ml/              # Machine learning module
│       ├── train.py     # Model training script
│       ├── features.py  # TF-IDF + structural feature extraction
│       └── Phishing_Email.csv  # Training dataset (Kaggle)
```

## Requirements

- Python 3.11+
- Django 5.2
- PostgreSQL (optional, SQLite for development)

## Installation

```bash
# Clone the repository
git clone https://codeberg.org/yushi_61/FakeFinder.git
cd FakeFinder/src

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

## Environment Setup

1. Copy the example environment file:
   ```bash
   cp FakeFinder/.env.example FakeFinder/.env
   ```

2. Configure your `.env` file:
   ```env
   DEBUG=True
   DJANGO_SECRET_KEY=your-secret-key-here
   DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1

   # Database (optional — defaults to SQLite)
   DB_NAME=fakefinder
   DB_USER=postgres
   DB_PASSWORD=your-password
   DB_HOST=localhost
   DB_PORT=5432
   ```

3. Run database migrations:
   ```bash
   python manage.py migrate
   ```

4. (Optional) Create a superuser:
   ```bash
   python manage.py createsuperuser
   ```

## Training the ML Model

Before scanning emails, you need to train the model:

```bash
python ml/train.py --data ml/Phishing_Email.csv --out ml/model.joblib --trees 200
```

This will:
- Load the Kaggle Phishing Email dataset
- Extract TF-IDF + structural features
- Train a calibrated Random Forest classifier
- Save the model to `ml/model.joblib`

**Dataset**: [Kaggle - Phishing Email Detection](https://www.kaggle.com/datasets/subhajournal/phishingemails) by Subhalaxmi Rout. Download and place `Phishing_Email.csv` in the `ml/` directory.

## Running the Server

```bash
python manage.py runserver
```

Access the application at `http://localhost:8000`

### Admin Credentials (Local/Demo)
- **Username**: `admin`
- **Password**: `admin_password_2026`

## Usage

1. Register an account or log in
2. Upload an `.eml` email file (max 10MB)
3. View the generated report with:
   - **Risk score**: LOW / MEDIUM / HIGH
   - **Numeric score**: 0–100 (0 = safe, 100 = phishing)
   - **Suspicious URLs** detected in the email
   - **Header anomalies** (sender domain, subject)
4. View and manage your scan history from the dashboard

## Risk Score Thresholds

| Score | Risk Level | Description |
|-------|------------|-------------|
| 0–29  | LOW        | Email appears safe |
| 30–71 | MEDIUM     | Ambiguous, review recommended |
| 72–100| HIGH       | Strong phishing signal |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET/POST | Upload email and view results |
| `/report/<id>/` | GET | View scan report |
| `/report/<id>/delete/` | POST | Delete a report |
| `/history/delete/` | POST | Delete all reports |
| `/login/` | POST | User login (rate-limited) |
| `/logout/` | POST | User logout |
| `/register/` | POST | User registration |