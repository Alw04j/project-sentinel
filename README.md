# Project Sentinel 🛡️

**AI-Driven Threat Intelligence & Vulnerability Management System**

Project Sentinel is a backend-focused web application built with Django that orchestrates automated network reconnaissance, processes security data, and surfaces actionable threat intelligence through a role-based dashboard.

## Key Features
* **Automated Reconnaissance:** Modules capable of automated data collection and structured vulnerability reporting.
* **Role-Based Access Control (RBAC):** Secure user authentication ensuring customized dashboard views for different administrative tiers.
* **Actionable Intelligence:** Cleans and formats raw security data into readable, dynamic web interfaces.
* **Ethical Scope:** Designed to operate strictly within isolated, on-premise sandboxed environments (dummy VMs) to ensure zero interference with live production networks.

## Tech Stack
* **Backend:** Python, Django
* **Database:** MySQL / SQLite
* **Frontend:** HTML, CSS, JavaScript (Basics)
* **Networking/Security Tools:** Integrated Python scripting for automated mapping.

## Setup Instructions
1. Clone the repository:
   `git clone <your-github-repo-url>`
2. Navigate to the directory:
   `cd project-sentinel`
3. Create a virtual environment and activate it:
   `python -m venv venv`
   `source venv/bin/activate`  # On Windows use: venv\Scripts\activate
4. Install dependencies:
   `pip install -r requirements.txt`
5. Run database migrations:
   `python manage.py migrate`
6. Start the development server:
   `python manage.py runserver`

*Note: This project is strictly for educational and controlled-environment deployment.*