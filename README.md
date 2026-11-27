

# 🛡️ URL Safety Checker

A Python-based web application that analyzes website URLs and identifies potentially suspicious characteristics using a risk-scoring system.

## 📌 About the Project

URL Safety Checker is designed to help users evaluate the potential risks associated with website URLs before visiting them.

The application analyzes URL characteristics, calculates a risk score, and classifies websites into different risk categories.

## ✨ Features

- URL safety analysis
- Risk score calculation
- Safe, Suspicious, and Dangerous classifications
- Invalid URL detection
- Detailed analysis of suspicious characteristics
- Scan history storage
- SQLite database integration
- User-friendly Streamlit interface
- Home, Scan History, About, and Help pages

## 🛠️ Technologies Used

- Python
- Streamlit
- SQLite
- HTML
- CSS

## 📂 Project Structure

```text
URL-Safety-Checker/
│
├── app.py
├── url_anlysr.py
├── database.py
├── requirements.txt
├── README.md
└── .gitignore
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/URL-Safety-Checker.git
```

### 2. Open the project folder

```bash
cd URL-Safety-Checker
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

For Windows:

```bash
venv\Scripts\activate
```

### 5. Install the required libraries

```bash
pip install -r requirements.txt
```

### 6. Run the application

```bash
streamlit run app.py
```

The application will open in your web browser.

## 📊 How It Works

1. Enter a website URL.
2. Click the Scan Website button.
3. The application analyzes the URL.
4. A risk score is calculated.
5. The website is classified according to its risk level.
6. Detailed analysis and previous scan history are displayed.

## 💾 Database

The application uses SQLite to store previous URL scan results, including:

- URL
- Domain
- Risk Score
- Status
- Scan Time

The database is created automatically when the application runs.

## ⚠️ Disclaimer

This application uses rule-based URL analysis for educational purposes. A Safe result does not guarantee that a website is completely secure. It is not a replacement for professional security tools or comprehensive malware detection.

## 👨‍💻 Author

Developed as a Python-based web development and cybersecurity project.