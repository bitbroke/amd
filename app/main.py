import os
import shutil
import uuid
from fastapi import FastAPI, UploadFile, File, HTTPException
from engine.detective import Detective
from engine.judge import PrivacyJudge

# Initialize the FastAPI app with metadata for the /docs page
app = FastAPI(
    title="AMD Security Engine API",
    description="Automated Malware Detection & Privacy Analysis System",
    version="1.0.0"
)

# Create a dedicated folder for temporary file processing
UPLOAD_DIR = "temp_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/")
def health_check():
    """Returns the status of the API."""
    return {
        "status": "Online",
        "engine": "AMD-v1",
        "components": ["Detective", "Lawyer", "Judge"]
    }

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Endpoint to upload a file for security analysis.
    1. Saves the file temporarily.
    2. Runs static analysis (Detective).
    3. Evaluates risks (Judge).
    4. Deletes the file and returns JSON results.
    """
    # 1. Generate a unique name to avoid overwriting files
    file_id = str(uuid.uuid4())
    temp_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")

    try:
        # 2. Write the uploaded content to the temp folder
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 3. Step 1 of 'The Brain': Static Analysis
        detective = Detective(temp_path)
        findings = detective.investigate()

        # 4. Step 2 of 'The Brain': Risk Scoring
        # We use 0.75 as a baseline score while we keep the ML model mocked
        mock_lawyer_score = 0.75 
        
        # 5. Step 3 of 'The Brain': Final Verdict
        judge = PrivacyJudge()
        verdict = judge.evaluate(findings, mock_lawyer_score)

        return {
            "file_info": {
                "name": file.filename,
                "size_bytes": os.path.getsize(temp_path)
            },
            "analysis": {
                "verdict": verdict,
                "threat_level": "LOW" if verdict == "SAFE" else "HIGH",
                "findings_found": len(findings)
            },
            "technical_report": {
                "signatures": findings
            }
        }

    except Exception as e:
        # If something crashes, return a 500 error
        raise HTTPException(status_code=500, detail=f"Internal Analysis Error: {str(e)}")

    finally:
        # 6. Safety Cleanup: Delete the file so no 'malware' stays on your server
        if os.path.exists(temp_path):
            os.remove(temp_path)