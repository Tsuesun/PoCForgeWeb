import React, { useState } from 'react'
import axios from 'axios'
import './App.css'

interface Commit {
  url: string
  sha: string
  message: string
  repo: string
  date: string
}

interface PoC {
  commit_url: string
  commit_sha: string
  vulnerable_function: string | null
  attack_vector: string
  vulnerable_code: string | null
  fixed_code: string | null
  test_case: string | null
  prerequisites: string[]
  reasoning: string
  method: string
}

interface Package {
  name: string
  ecosystem: string
  vulnerable_versions: string
  patched_versions: string
  commits: Commit[]
  pocs: PoC[]
}

interface CVE {
  cve_id: string
  summary: string
  severity: string
  published_at: string
  packages: Package[]
  pocs_generated: number
}

interface Summary {
  total_cves: number
  total_packages: number
  pocs_generated: number
  success_rate: number
}

interface SearchParams {
  hours: number
  target_cve: string
  timestamp: string
}

interface PoCForgeResponse {
  search_params: SearchParams
  cves: CVE[]
  summary: Summary
}

interface AnalyzeResponse {
  success: boolean
  data?: PoCForgeResponse
  error?: string
}

function App() {
  const [cveId, setCveId] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AnalyzeResponse | null>(null)
  const [validationError, setValidationError] = useState('')

  const validateCveFormat = (cve: string): boolean => {
    const cvePattern = /^CVE-\d{4}-\d{4,}$/i
    return cvePattern.test(cve.trim())
  }

  const handleCveChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setCveId(value)
    
    if (value.trim() && !validateCveFormat(value)) {
      setValidationError('Invalid CVE format. Expected format: CVE-YYYY-NNNN (e.g., CVE-2024-1234)')
    } else {
      setValidationError('')
    }
  }

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!cveId.trim()) return

    if (!validateCveFormat(cveId)) {
      setValidationError('Invalid CVE format. Expected format: CVE-YYYY-NNNN (e.g., CVE-2024-1234)')
      return
    }

    setLoading(true)
    setResult(null)
    setValidationError('')

    try {
      const response = await axios.post<AnalyzeResponse>('http://localhost:8000/analyze', {
        cve_id: cveId.toUpperCase()
      })
      setResult(response.data)
    } catch (error) {
      setResult({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>PoCForge Web</h1>
        <p>Transform CVE fix commits into practical PoC demonstrations</p>
      </header>

      <main>
        <form onSubmit={handleAnalyze} className="analyze-form">
          <div className="form-group">
            <label htmlFor="cve-id">CVE ID:</label>
            <input
              id="cve-id"
              type="text"
              value={cveId}
              onChange={handleCveChange}
              placeholder="e.g., CVE-2023-1234"
              disabled={loading}
              className={validationError ? 'error' : ''}
            />
            {validationError && (
              <div className="validation-error">
                {validationError}
              </div>
            )}
          </div>
          <button type="submit" disabled={loading || !cveId.trim() || !!validationError}>
            {loading ? 'Analyzing...' : 'Analyze CVE'}
          </button>
        </form>

        {result && (
          <div className="results">
            {result.success && result.data ? (
              <div className="success-result">
                {result.data.cves.map((cve, cveIndex) => (
                  <div key={cveIndex} className="cve-section">
                    <h2>{cve.cve_id}</h2>
                    <div className="cve-details">
                      <p><strong>Summary:</strong> {cve.summary}</p>
                      <p><strong>Severity:</strong> <span className={`severity-${cve.severity.toLowerCase()}`}>{cve.severity}</span></p>
                      <p><strong>Published:</strong> {new Date(cve.published_at).toLocaleDateString()}</p>
                      <p><strong>PoCs Generated:</strong> {cve.pocs_generated}</p>
                    </div>

                    {cve.packages.map((pkg, pkgIndex) => (
                      <div key={pkgIndex} className="package-section">
                        <h3>Package: {pkg.name} ({pkg.ecosystem})</h3>
                        <div className="package-details">
                          <p><strong>Vulnerable Versions:</strong> {pkg.vulnerable_versions}</p>
                          <p><strong>Patched Versions:</strong> {pkg.patched_versions}</p>
                        </div>

                        <div className="commits-section">
                          <h4>Fix Commits</h4>
                          {pkg.commits.map((commit, commitIndex) => (
                            <div key={commitIndex} className="commit-item">
                              <p><strong>Repo:</strong> {commit.repo}</p>
                              <p><strong>Message:</strong> {commit.message}</p>
                              <p><strong>SHA:</strong> <code>{commit.sha}</code></p>
                              <p><strong>URL:</strong> <a href={commit.url} target="_blank" rel="noopener noreferrer">{commit.url}</a></p>
                            </div>
                          ))}
                        </div>

                        <div className="pocs-section">
                          <h4>Proof of Concepts</h4>
                          {pkg.pocs.map((poc, pocIndex) => (
                            <div key={pocIndex} className="poc-item">
                              <div className="poc-header">
                                <h5>PoC #{pocIndex + 1}</h5>
                                <p><strong>Method:</strong> {poc.method}</p>
                                {poc.vulnerable_function && (
                                  <p><strong>Vulnerable Function:</strong> <code>{poc.vulnerable_function}</code></p>
                                )}
                              </div>
                              
                              <div className="poc-content">
                                <div className="result-section">
                                  <h6>Attack Vector:</h6>
                                  <p>{poc.attack_vector}</p>
                                </div>

                                {poc.vulnerable_code && (
                                  <div className="result-section">
                                    <h6>Vulnerable Code:</h6>
                                    <pre><code>{poc.vulnerable_code}</code></pre>
                                  </div>
                                )}

                                {poc.fixed_code && (
                                  <div className="result-section">
                                    <h6>Fixed Code:</h6>
                                    <pre><code>{poc.fixed_code}</code></pre>
                                  </div>
                                )}

                                {poc.test_case && (
                                  <div className="result-section">
                                    <h6>Test Case:</h6>
                                    <pre><code>{poc.test_case}</code></pre>
                                  </div>
                                )}

                                <div className="result-section">
                                  <h6>Prerequisites:</h6>
                                  <ul>
                                    {poc.prerequisites.map((prereq, i) => (
                                      <li key={i}>{prereq}</li>
                                    ))}
                                  </ul>
                                </div>

                                <div className="result-section">
                                  <h6>Analysis Reasoning:</h6>
                                  <p>{poc.reasoning}</p>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            ) : (
              <div className="error-result">
                <h2>Analysis Failed</h2>
                <p>{result.error}</p>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

export default App
