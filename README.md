
# PortMaster-Analyst

**PortMaster-Analyst** is a lightweight Flask-based web application designed to analyze and visualize network port activity. It provides a simple and interactive interface for understanding port usage on a system.

## Features

- Web interface to visualize and analyze port activity.
- Dynamic tables and visual components.
- Search and filtering capabilities for better data analysis.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/paizy-hub/PortMaster-Analyst.git
cd PortMaster-Analyst
```

### 2. Create and activate a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Linux/macOS
venv\Scripts\activate     # On Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

The app will be available at `http://localhost:5000`.

## Project Structure

```
PortMaster-Analyst/
├── app.py                 # Main Flask application
├── templates/             # HTML templates (Jinja2)
│   └── index.html
├── static/                # Static files (CSS, JS)
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
