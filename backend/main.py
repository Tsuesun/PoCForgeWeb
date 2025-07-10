from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import subprocess
import json
import os

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
        # For now, mock the PoCForge call since we don't have it installed
        # In production, this would be:
        # result = subprocess.run(["python", "pocforge.py", "--json", request.cve_id], 
        #                        capture_output=True, text=True, timeout=300)
        
        # Mock response based on actual PoCForge structure
        mock_response = PoCForgeResponse(
            search_params=SearchParams(
                hours=24,
                target_cve=request.cve_id,
                timestamp="2025-07-09T07:28:55.488209+00:00"
            ),
            cves=[
                CVE(
                    cve_id=request.cve_id,
                    summary="Mock vulnerability in example package",
                    severity="HIGH",
                    published_at="2025-07-08T20:47:53+00:00",
                    packages=[
                        Package(
                            name="example-package",
                            ecosystem="npm",
                            vulnerable_versions="< 2.5.0",
                            patched_versions="2.5.0",
                            commits=[
                                Commit(
                                    url="https://github.com/example/repo/commit/abc123",
                                    sha="abc123",
                                    message="Fix vulnerability in example function",
                                    repo="example/repo",
                                    date="2025-07-08"
                                )
                            ],
                            pocs=[
                                PoC(
                                    commit_url="https://github.com/example/repo/commit/abc123",
                                    commit_sha="abc123",
                                    vulnerable_function="executeCommand",
                                    attack_vector="Command injection via malicious input",
                                    vulnerable_code="const result = execSync(userInput);",
                                    fixed_code="const result = execFileSync(command, args);",
                                    test_case="const malicious = \"ls; rm -rf /\"; executeCommand(malicious);",
                                    prerequisites=["Access to vulnerable function", "Valid input parameters"],
                                    reasoning="The original code used string concatenation with execSync which allows command injection",
                                    method="git_extraction"
                                )
                            ]
                        )
                    ],
                    pocs_generated=1
                )
            ],
            summary=Summary(
                total_cves=1,
                total_packages=1,
                pocs_generated=1,
                success_rate=100.0
            )
        )
        
        return AnalyzeResponse(success=True, data=mock_response)
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Analysis timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/")
async def root():
    return {"message": "PoCForge Web API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)