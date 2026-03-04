"""FastAPI application exposing analysis endpoints.

The endpoint /analyze accepts JSON with an `image_path` pointing to either
an on-disk mounted directory (for development) or a disk image file (dd, etc.).
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .extractor import FilesystemAccessor
from .detector import detect_os, detect_tools
from .classifier import classify_findings
from .report import build_report
import traceback
import tempfile
import shutil
import os


class AnalyzeRequest(BaseModel):
    image_path: str


app = FastAPI(title="OS Forensics Prototype API")

# Allow the UI dev server to call this API during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        os_info = detect_os(fs)
        findings = detect_tools(fs)
        classified = classify_findings(findings)
        report = build_report(os_info, classified)
        return report.dict()
    except Exception as e:
        tb = traceback.format_exc()
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": tb})



@app.post("/upload")
def upload_image(file: UploadFile = File(...)):
    """Accept an uploaded image file, store it temporarily, and analyze it.

    Returns the same report structure as /analyze.
    """
    # write uploaded file to temp file
    tmp_dir = tempfile.mkdtemp(prefix="osforensics_upload_")
    try:
        tmp_path = os.path.join(tmp_dir, file.filename)
        with open(tmp_path, "wb") as out_f:
            shutil.copyfileobj(file.file, out_f)

        fs = FilesystemAccessor(tmp_path)
        os_info = detect_os(fs)
        findings = detect_tools(fs)
        classified = classify_findings(findings)
        report = build_report(os_info, classified)
        return report.dict()
    except Exception as e:
        tb = traceback.format_exc()
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": tb})
    finally:
        try:
            file.file.close()
        except Exception:
            pass
        # cleanup temporary files
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass
