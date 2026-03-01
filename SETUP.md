for first time setup 

Step 1: Install Python
Download and install Python (3.9 or newer) from python.org.

CRITICAL: During installation, make sure to check the box that says "Add Python to PATH" at the bottom of the installer window.

Step 2: Download the Code & Open Terminal
Download or move the AMD_HARDCODE (or PrivacyLens) project folder to the new PC.

Open the folder in VS Code.

Open a new terminal inside VS Code by pressing Ctrl + ` (the backtick key) or going to Terminal > New Terminal at the top.

Step 3: Create a requirements.txt File
To make installing the dependencies a 1-click process, create a file named requirements.txt in the main project folder and paste this inside:

Plaintext
# requirements.txt
torch==2.10.0
transformers==5.2.0
pefile==2024.8.26
psutil==7.2.2
streamlit==1.54.0
plotly==6.5.2
pandas==2.3.3
Step 4: The First-Time Setup Commands
In the VS Code terminal, tell the user to run these commands one by one:

1. Create a Virtual Environment:
This creates an isolated bubble for the project so it doesn't mess with other Python apps on the PC.

PowerShell
python -m venv venv
2. Activate the Environment:

PowerShell
.\venv\Scripts\activate
(They should see (venv) appear at the start of their terminal line.)

3. Install the Required Libraries:
This will read the requirements.txt file and download all the AI models, UI tools, and system scanners. (This might take a few minutes depending on internet speed).

PowerShell
pip install -r requirements.txt
Step 5: Run the App!
Once the installation finishes, the workspace is fully set up. They can run the app just like you do:

Run the backend audit:

PowerShell
python main.py
Launch the Dashboard:

PowerShell
streamlit run ui/dashboard.py




for every time setup

1. Prerequisites
Windows OS

Python 3.9+

2. Environment Setup
Clone the repository and set up your virtual environment:

PowerShell
# Create a virtual environment
python -m venv venv

# Activate it
.\venv\Scripts\activate
3. Install Dependencies
PowerShell
pip install transformers torch pefile psutil streamlit plotly pandas
💻 Usage
Option 1: The 1-Click Startup
If you have created the start_privacylens.bat file, simply double-click it from your file explorer to launch the backend and frontend simultaneously.

Option 2: Manual Execution
1. Run the Headless Audit Pipeline:
This will scan the target, monitor it for 10 seconds, and generate a report.json file.

PowerShell
python main.py
2. Launch the Interactive Dashboard:
This will open the Streamlit UI in your browser (usually http://localhost:8501) to visualize the Neuro-Symbolic Alignment, Risk Distribution, and Audit Ledger.

PowerShell
streamlit run ui/dashboard.py