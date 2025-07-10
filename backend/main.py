from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from typing import List, Optional
import subprocess
import json
import os
import re

app = FastAPI(title="PoCForge Web API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    cve_id: str
    
    @field_validator('cve_id')
    @classmethod
    def validate_cve_format(cls, v):
        if not v:
            raise ValueError('CVE ID cannot be empty')
        
        # CVE format: CVE-YYYY-NNNN (where YYYY is year and NNNN is at least 4 digits)
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        if not re.match(cve_pattern, v.upper()):
            raise ValueError('Invalid CVE format. Expected format: CVE-YYYY-NNNN (e.g., CVE-2024-1234)')
        
        return v.upper()

class Commit(BaseModel):
    url: str
    sha: str
    message: str
    repo: str
    date: str

class PoC(BaseModel):
    commit_url: str
    commit_sha: str
    vulnerable_function: Optional[str]
    attack_vector: str
    vulnerable_code: Optional[str]
    fixed_code: Optional[str]
    test_case: Optional[str]
    prerequisites: List[str]
    reasoning: str
    method: str

class Package(BaseModel):
    name: str
    ecosystem: str
    vulnerable_versions: str
    patched_versions: str
    commits: List[Commit]
    pocs: List[PoC]

class CVE(BaseModel):
    cve_id: str
    summary: str
    severity: str
    published_at: str
    packages: List[Package]
    pocs_generated: int

class Summary(BaseModel):
    total_cves: int
    total_packages: int
    pocs_generated: int
    success_rate: float

class SearchParams(BaseModel):
    hours: int
    target_cve: str
    timestamp: str

class PoCForgeResponse(BaseModel):
    search_params: SearchParams
    cves: List[CVE]
    summary: Summary

class AnalyzeResponse(BaseModel):
    success: bool
    data: Optional[PoCForgeResponse] = None
    error: Optional[str] = None

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_cve(request: AnalyzeRequest):
    try:
        # Call PoCForge CLI from the submodule
        pocforge_dir = os.path.join(os.path.dirname(__file__), "PoCForge")
        result = subprocess.run(
            ["uv", "run", "main.py", "--cve", request.cve_id, "--json"],
            cwd=pocforge_dir,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=500, 
                detail=f"PoCForge failed: {result.stderr}"
            )
        
        # Parse the JSON response from PoCForge
        pocforge_data = json.loads(result.stdout)
        
        # Convert PoCForge response to our expected format
        response_data = PoCForgeResponse(**pocforge_data)
        
        return AnalyzeResponse(success=True, data=response_data)
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Analysis timeout")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Invalid JSON response: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/")
async def root():
    return {"message": "PoCForge Web API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)