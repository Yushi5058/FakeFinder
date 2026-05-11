# FakeFinder

A Django-based email scanner that analyzes `.eml` files to detect phishing and fake emails by examining suspicious URLs and header anomalies.

## Features

- Upload and analyze `.eml` email files
- Extract and flag suspicious URLs
- Detect header anomalies (sender domain analysis)
- Assign risk scores: LOW, MEDIUM, HIGH
- Web-based interface for file upload and report viewing

## Requirements

- Python 3.11+
- PostgreSQL (optional, SQLite for development)
- Django 6.0

## Installation

```bash
# Clone the repository
git clone https://codeberg.org/yushi_61/FakeFinder.git
cd FakeFinder

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
cd FakeFinder
pip install -r requirements.txt
```

## Environment Setup

1. **Copy the example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Configure your `.env` file with the following variables:**
   ```env
   DEBUG=True
   SECRET_KEY=your-secret-key-here
   ALLOWED_HOSTS=localhost,127.0.0.1

   # Database (optional - defaults to SQLite)
   DB_NAME=fakefinder
   DB_USER=postgres
   DB_PASSWORD=your-password
   DB_HOST=localhost
   DB_PORT=5432

   # JWT Authentication
   JWT_SECRET_KEY=your-jwt-secret
   JWT_ALGORITHM=HS256
   JWT_ACCESS_TOKEN_LIFETIME=60
   ```

3. **Run database migrations:**
   ```bash
   python manage.py migrate
   ```

4. **Create a superuser (optional):**
   ```bash
   python manage.py createsuperuser
   ```

5. **Start the development server:**
   ```bash
   python manage.py runserver
   ```

6. Access the application at `http://localhost:8000`

## Usage

1. Open the web interface in your browser
2. Upload an `.eml` email file
3. View the generated report with risk score and detected anomalies