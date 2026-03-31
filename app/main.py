import base64
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

import opengradient as og

load_dotenv()

app = FastAPI(title="SafeCode")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "change-me"),
    same_site="lax",
    https_only=False,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"

OG_PRIVATE_KEY = os.getenv("OG_PRIVATE_KEY", "").strip()
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "").strip()
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "").strip()
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000").strip()

_APPROVAL_DONE = False

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class RepoScanRequest(BaseModel):
    owner: str
    repo: str
    branch: Optional[str] = None
    pr_number: Optional[int] = None
    focus: Optional[str] = (
        "Audit this codebase or pull request for bugs, security issues, dependency risks, "
        "config mistakes, and breaking changes. Explain in plain English."
    )


class SnippetScanRequest(BaseModel):
    code: str
    language: str
    error_message: Optional[str] = ""
    focus: Optional[str] = "Find likely bugs, explain why they happen, and suggest fixes."


def get_user_token(request: Request) -> str:
    token = request.session.get("github_access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not connected to GitHub")
    return token


def github_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_get(url: str, token: str, params: Optional[Dict[str, Any]] = None) -> Any:
    response = requests.get(url, headers=github_headers(token), params=params, timeout=60)
    if response.status_code >= 400:
        raise HTTPException(status_code=400, detail=f"GitHub error: {response.status_code} - {response.text}")
    return response.json()

def github_paginated_get(url: str, token: str, per_page: int = 100, max_pages: int = 5) -> List[Dict[str, Any]]:
    items = []
    for page in range(1, max_pages + 1):
        data = github_get(url, token, params={"per_page": per_page, "page": page})
        if not isinstance(data, list) or not data:
            break
        items.extend(data)
        if len(data) < per_page:
            break
    return items


def github_get_user_repos(token: str) -> List[Dict[str, Any]]:
    repos = github_paginated_get("https://api.github.com/user/repos", token, per_page=100, max_pages=5)

    cleaned = []
    for repo in repos:
        cleaned.append({
            "owner": repo.get("owner", {}).get("login", ""),
            "name": repo.get("name", ""),
            "full_name": repo.get("full_name", ""),
            "private": repo.get("private", False),
            "default_branch": repo.get("default_branch", ""),
            "updated_at": repo.get("updated_at", ""),
        })

    cleaned.sort(key=lambda x: x.get("updated_at", ""), reverse=True)
    return cleaned    

def get_default_branch(token: str, owner: str, repo: str) -> str:
    data = github_get(f"https://api.github.com/repos/{owner}/{repo}", token)
    return data["default_branch"]


def get_branch_tree_sha(token: str, owner: str, repo: str, branch: str) -> str:
    data = github_get(f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}", token)
    return data["commit"]["commit"]["tree"]["sha"]


def get_repo_tree(token: str, owner: str, repo: str, tree_sha: str) -> List[Dict[str, Any]]:
    data = github_get(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}",
        token,
        params={"recursive": "1"},
    )
    return data.get("tree", [])


def get_file_content(token: str, owner: str, repo: str, path: str, ref: str) -> str:
    try:
        data = github_get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            token,
            params={"ref": ref},
        )
    except HTTPException as e:
        # Missing optional files should not crash the whole scan
        if e.status_code == 400 and "404" in str(e.detail):
            return ""
        raise

    if not isinstance(data, dict):
        return ""

    if data.get("type") != "file":
        return ""

    content = data.get("content", "")
    encoding = data.get("encoding", "")

    if encoding == "base64" and content:
        try:
            return base64.b64decode(content).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    return ""


def get_pr_files(token: str, owner: str, repo: str, pr_number: int) -> List[Dict[str, Any]]:
    files = []
    page = 1
    while True:
        data = github_get(
            f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files",
            token,
            params={"per_page": 100, "page": page},
        )
        if not data:
            break
        files.extend(data)
        if len(data) < 100:
            break
        page += 1
    return files


def get_pr_details(token: str, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
    return github_get(f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}", token)


def should_include_file(path: str) -> bool:
    blocked = (
        "node_modules/",
        ".next/",
        "dist/",
        "build/",
        ".git/",
        "coverage/",
        ".venv/",
        "venv/",
        "__pycache__/",
        "vendor/",
        "target/",
        ".cache/",
        ".turbo/",
    )
    if any(part in path for part in blocked):
        return False

    important_files = {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        "tsconfig.json",
        "next.config.js",
        "next.config.mjs",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".env.example",
    }

    allowed_ext = (
        ".py", ".js", ".ts", ".tsx", ".jsx",
        ".json", ".toml", ".yml", ".yaml",
        ".md", ".ini", ".cfg", ".sh"
    )

    return path in important_files or path.endswith(allowed_ext)


def score_path(path: str) -> int:
    score = 0
    exact = {
        "package.json": 100,
        "requirements.txt": 100,
        "pyproject.toml": 100,
        "package-lock.json": 95,
        "pnpm-lock.yaml": 95,
        "yarn.lock": 95,
        "tsconfig.json": 90,
        "next.config.js": 90,
        "next.config.mjs": 90,
        "Dockerfile": 90,
        ".env.example": 85,
    }
    if path in exact:
        score += exact[path]

    for word in ["src", "app", "api", "server", "main", "lib", "utils", "components", "pages"]:
        if word in path.lower():
            score += 10

    if path.endswith((".py", ".js", ".ts", ".tsx", ".jsx")):
        score += 30

    if path.endswith((".json", ".toml", ".yml", ".yaml")):
        score += 15

    return score


def build_local_repo_from_github(
    token: str,
    owner: str,
    repo: str,
    branch: str,
    target_dir: str,
    pr_number: Optional[int] = None,
) -> List[str]:
    selected_paths: List[str] = []
    ref_to_use = branch

    if pr_number:
        pr_details = get_pr_details(token, owner, repo, pr_number)
        ref_to_use = pr_details.get("head", {}).get("ref", branch)

        pr_files = get_pr_files(token, owner, repo, pr_number)
        pr_paths = [f["filename"] for f in pr_files if should_include_file(f.get("filename", ""))]
        selected_paths.extend(pr_paths)

        for extra in [
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "requirements.txt",
            "pyproject.toml",
            "tsconfig.json",
            "next.config.js",
            "next.config.mjs",
            "Dockerfile",
            ".env.example",
        ]:
            if extra not in selected_paths:
                selected_paths.append(extra)
    else:
        tree_sha = get_branch_tree_sha(token, owner, repo, branch)
        tree = get_repo_tree(token, owner, repo, tree_sha)
        candidates = []

        for item in tree:
            if item.get("type") != "blob":
                continue
            path = item.get("path", "")
            size = item.get("size", 0) or 0
            if size > 300_000:
                continue
            if should_include_file(path):
                candidates.append(path)

        selected_paths = sorted(candidates, key=score_path, reverse=True)[:120]

    written = []
    seen = set()

    for path in selected_paths:
        if path in seen:
            continue
        seen.add(path)

        content = get_file_content(token, owner, repo, path, ref_to_use)
        if not content.strip():
            continue

        full_path = os.path.join(target_dir, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with open(full_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)

        written.append(path)

    return written


def run_command(cmd: List[str], cwd: str, timeout: int = 600) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "Command timed out"}
    except Exception as e:
        return {"returncode": 1, "stdout": "", "stderr": str(e)}


def run_semgrep(scan_dir: str) -> Dict[str, Any]:
    result = run_command(
        ["semgrep", "scan", "--config", "auto", "--json", "--metrics=off", "."],
        cwd=scan_dir,
        timeout=900,
    )
    try:
        return json.loads(result["stdout"]) if result["stdout"] else {"results": [], "errors": [result["stderr"]]}
    except Exception:
        return {"results": [], "errors": [result["stderr"] or "Failed to parse Semgrep output"]}


def run_bandit(scan_dir: str) -> Dict[str, Any]:
    result = run_command(["bandit", "-r", ".", "-f", "json"], cwd=scan_dir, timeout=900)
    try:
        return json.loads(result["stdout"]) if result["stdout"] else {"results": [], "errors": [result["stderr"]]}
    except Exception:
        return {"results": [], "errors": [result["stderr"] or "Failed to parse Bandit output"]}


def run_trivy(scan_dir: str) -> Dict[str, Any]:
    result = run_command(
        [
            "trivy", "fs",
            "--format", "json",
            "--severity", "HIGH,CRITICAL",
            "--scanners", "vuln,misconfig,secret",
            ".",
        ],
        cwd=scan_dir,
        timeout=1200,
    )
    try:
        return json.loads(result["stdout"]) if result["stdout"] else {"Results": [], "Errors": [result["stderr"]]}
    except Exception:
        return {"Results": [], "Errors": [result["stderr"] or "Failed to parse Trivy output"]}


def normalize_semgrep(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    for item in data.get("results", []):
        findings.append({
            "tool": "semgrep",
            "severity": (item.get("extra", {}).get("severity") or "MEDIUM").lower(),
            "title": item.get("check_id", "Semgrep finding"),
            "file": item.get("path", ""),
            "line": item.get("start", {}).get("line", 0),
            "description": item.get("extra", {}).get("message", ""),
            "fix_hint": item.get("extra", {}).get("fix", ""),
        })
    return findings


def normalize_bandit(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    for item in data.get("results", []):
        findings.append({
            "tool": "bandit",
            "severity": (item.get("issue_severity") or "MEDIUM").lower(),
            "title": item.get("test_id", "Bandit finding"),
            "file": item.get("filename", ""),
            "line": item.get("line_number", 0),
            "description": item.get("issue_text", ""),
            "fix_hint": item.get("more_info", ""),
        })
    return findings


def normalize_trivy(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    for block in data.get("Results", []):
        target = block.get("Target", "")

        for item in block.get("Vulnerabilities", []) or []:
            findings.append({
                "tool": "trivy",
                "severity": (item.get("Severity") or "HIGH").lower(),
                "title": item.get("VulnerabilityID", "Trivy vulnerability"),
                "file": target,
                "line": 0,
                "description": item.get("Title") or item.get("Description") or "",
                "fix_hint": item.get("FixedVersion", ""),
            })

        for item in block.get("Misconfigurations", []) or []:
            findings.append({
                "tool": "trivy",
                "severity": (item.get("Severity") or "HIGH").lower(),
                "title": item.get("ID", "Trivy misconfiguration"),
                "file": target,
                "line": 0,
                "description": item.get("Title") or item.get("Description") or "",
                "fix_hint": item.get("Resolution", ""),
            })

        for item in block.get("Secrets", []) or []:
            findings.append({
                "tool": "trivy",
                "severity": "high",
                "title": item.get("RuleID", "Trivy secret"),
                "file": target,
                "line": item.get("StartLine", 0),
                "description": item.get("Title") or "Potential secret detected",
                "fix_hint": "Remove the secret from code and rotate it immediately.",
            })

    return findings


def normalize_all(semgrep_data: Dict[str, Any], bandit_data: Dict[str, Any], trivy_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    findings.extend(normalize_semgrep(semgrep_data))
    findings.extend(normalize_bandit(bandit_data))
    findings.extend(normalize_trivy(trivy_data))

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)
    return findings


def get_og_llm():
    if not OG_PRIVATE_KEY:
        raise HTTPException(status_code=500, detail="Missing OG_PRIVATE_KEY in environment")

    return og.LLM(private_key=OG_PRIVATE_KEY)

_OG_APPROVAL_DONE = False

def ensure_og_approval_once(llm):
    global _OG_APPROVAL_DONE
    if _OG_APPROVAL_DONE:
        return

    llm.ensure_opg_approval(min_allowance=5)
    _OG_APPROVAL_DONE = True

def get_settlement_mode(mode: str):
    if mode in ["snippet", "pr"]:
        return og.x402SettlementMode.INDIVIDUAL_FULL
    return og.x402SettlementMode.BATCH_HASHED

def ensure_opg_approval_once(client) -> None:
    global _APPROVAL_DONE
    if _APPROVAL_DONE:
        return
    try:
        if hasattr(client, "llm") and hasattr(client.llm, "ensure_opg_approval"):
            client.llm.ensure_opg_approval(opg_amount=5)
        _APPROVAL_DONE = True
    except Exception:
        pass

def build_snippet_evidence_payload(code: str, language: str, findings: List[Dict[str, Any]], error_message: str = "") -> Dict[str, Any]:
    return {
        "mode": "snippet",
        "language": language,
        "error_message": error_message or "",
        "findings": findings[:10],
        "code": code[:6000],
        "severity_groups": group_findings_by_severity(findings),
        "risk_score": calculate_risk_score(findings, mode="snippet"),
        "status_label": build_status_label("snippet", calculate_risk_score(findings, mode="snippet")),
    }

def build_repo_evidence_payload(
    repo_name: str,
    findings: List[Dict[str, Any]],
    scanner_counts: Dict[str, Any],
    sample_files: Dict[str, str]
) -> Dict[str, Any]:
    return {
        "mode": "repo",
        "repo": repo_name,
        "scanner_counts": scanner_counts,
        "findings": findings[:20],
        "severity_groups": group_findings_by_severity(findings),
        "risk_score": calculate_risk_score(findings, mode="repo"),
        "status_label": build_status_label("repo", calculate_risk_score(findings, mode="repo")),
        "sample_files": {
            path: content[:3000] for path, content in sample_files.items()
        },
    }

def build_pr_evidence_payload(
    repo_name: str,
    pr_number: int,
    changed_files: List[str],
    touched_findings: List[Dict[str, Any]],
    existing_findings: List[Dict[str, Any]],
    scanner_counts: Dict[str, Any]
) -> Dict[str, Any]:
    pr_relevant = touched_findings if touched_findings else existing_findings

    return {
        "mode": "pr",
        "repo": repo_name,
        "pr_number": pr_number,
        "changed_files": changed_files,
        "touched_findings": touched_findings[:10],
        "existing_findings": existing_findings[:10],
        "scanner_counts": scanner_counts,
        "risk_score": calculate_risk_score(pr_relevant, mode="pr"),
        "status_label": build_status_label(
            "pr",
            calculate_risk_score(pr_relevant, mode="pr"),
            pr_has_touched_findings=len(touched_findings) > 0,
        ),
        "severity_groups": group_findings_by_severity(pr_relevant),
    }

def build_opengradient_prompt(mode: str, evidence_payload: Dict[str, Any]) -> Dict[str, str]:
    if mode == "snippet":
        system_prompt = """
You are SafeCode's verified AI reasoning engine.

You will receive:
- the programming language
- scanner and heuristic findings
- the code snippet
- optional user error message

Your job:
- explain the real issues clearly
- prioritize the most important risks
- provide practical debugging or remediation steps
- return ONLY valid JSON
- do not wrap the JSON in markdown

Required JSON schema:
{
  "summary": "string",
  "status_label": "Looks Safe | Low Risk | Moderate Risk | High Risk",
  "risk_score": 0,
  "top_risks": [
    {
      "title": "string",
      "severity": "critical|high|medium|low",
      "file": "string",
      "why_it_matters": "string",
      "fix": "string"
    }
  ],
  "recommended_actions": ["string"],
  "safe_fix_examples": ["string"],
  "user_explanation": "string"
}
"""
        user_prompt = f"""
Snippet evidence payload:
{json.dumps(evidence_payload, ensure_ascii=False, indent=2)}
"""
        return {
            "system": system_prompt,
            "user": user_prompt,
        }

    if mode == "repo":
        system_prompt = """
You are SafeCode's verified AI reasoning engine.

You will receive:
- repository-level scanner findings
- severity group counts
- scanner counts
- sample files
- current repo risk score and status

Your job:
- summarize the repo's most important risks
- prioritize what needs fixing first
- distinguish urgent issues from lower-priority items
- return ONLY valid JSON
- do not wrap the JSON in markdown

Required JSON schema:
{
  "summary": "string",
  "status_label": "Healthy | Monitor | Needs Attention | Critical",
  "risk_score": 0,
  "top_risks": [
    {
      "title": "string",
      "severity": "critical|high|medium|low",
      "file": "string",
      "why_it_matters": "string",
      "fix": "string"
    }
  ],
  "recommended_actions": ["string"],
  "priority_issues": ["string"],
  "what_can_wait": ["string"],
  "user_explanation": "string"
}
"""
        user_prompt = f"""
Repository evidence payload:
{json.dumps(evidence_payload, ensure_ascii=False, indent=2)}
"""
        return {
            "system": system_prompt,
            "user": user_prompt,
        }

    if mode == "pr":
        system_prompt = """
You are SafeCode's verified AI reasoning engine.

You will receive:
- pull request metadata
- changed files
- findings tied to files changed by the PR
- existing repo findings not directly tied to the PR
- scanner counts and severity groups

Your job:
- determine whether the PR appears safe to merge
- clearly separate PR-specific risk from existing repo risk
- prioritize what needs attention before merge
- return ONLY valid JSON
- do not wrap the JSON in markdown

Required JSON schema:
{
  "summary": "string",
  "status_label": "Approve | Review Needed | Caution | Block",
  "risk_score": 0,
  "top_risks": [
    {
      "title": "string",
      "severity": "critical|high|medium|low",
      "file": "string",
      "why_it_matters": "string",
      "fix": "string"
    }
  ],
  "recommended_actions": ["string"],
  "pr_specific_risks": ["string"],
  "existing_repo_risks": ["string"],
  "decision_reasoning": "string",
  "user_explanation": "string"
}
"""
        user_prompt = f"""
PR evidence payload:
{json.dumps(evidence_payload, ensure_ascii=False, indent=2)}
"""
        return {
            "system": system_prompt,
            "user": user_prompt,
        }

    raise ValueError(f"Unsupported mode: {mode}")

import asyncio

def generate_verified_reasoning(mode: str, evidence_payload: Dict[str, Any]) -> Dict[str, Any]:
    if os.getenv("OG_ENABLE_VERIFIED_REASONING", "true").lower() != "true":
        fallback = make_human_fallback_summary(mode, evidence_payload.get("findings", []))
        fallback["verification_mode"] = "fallback"
        fallback["user_explanation"] = "Verified reasoning is disabled in this environment."
        return fallback

    llm = get_og_llm()
    ensure_og_approval_once(llm)
    prompt = build_opengradient_prompt(mode, evidence_payload)

    async def _run_chat():
        return await llm.chat(
            model=og.TEE_LLM.GPT_5,
            messages=[
                {"role": "system", "content": prompt["system"]},
                {"role": "user", "content": prompt["user"]},
            ],
            max_tokens=1800,
            x402_settlement_mode=get_settlement_mode(mode),
        )

    try:
        result = asyncio.run(_run_chat())

        raw = result.chat_output["content"]
        payment_hash = getattr(result, "transaction_hash", None)

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}")
            if start != -1 and end != -1 and end > start:
                parsed = json.loads(raw[start:end + 1])
            else:
                raise ValueError("OpenGradient returned non-JSON output")

        parsed["payment_hash"] = payment_hash
        parsed["verification_mode"] = "verified"

        if "recommended_actions" in parsed and "quick_fixes" not in parsed:
            parsed["quick_fixes"] = parsed["recommended_actions"]

        if "user_explanation" in parsed and "vibe_coder_explanation" not in parsed:
            parsed["vibe_coder_explanation"] = parsed["user_explanation"]

        return parsed

    except Exception as e:
        fallback = make_human_fallback_summary(mode, evidence_payload.get("findings", []))
        fallback["verification_mode"] = "fallback"
        fallback["debug_error"] = str(e)

        if mode == "repo":
            fallback["user_explanation"] = (
                "AI reasoning is temporarily unavailable, but the repository findings below are still valid and can be reviewed."
            )
        elif mode == "pr":
            fallback["user_explanation"] = (
                "AI reasoning is temporarily unavailable, but the PR findings below are still valid and can be reviewed."
            )
        else:
            fallback["user_explanation"] = (
                "AI reasoning is temporarily unavailable, but the snippet findings below are still valid and can be reviewed."
            )

        return fallback

def explain_with_opengradient(context_name: str, focus: str, findings: List[Dict[str, Any]], sample_files: Dict[str, str]) -> Dict[str, Any]:
    client = get_og_client()
    ensure_opg_approval_once(client)

    findings_text = json.dumps(findings[:20], ensure_ascii=False, indent=2)

    sample_parts = []
    for path, content in sample_files.items():
        sample_parts.append(f"FILE: {path}\n```\n{content[:4000]}\n```")
    sample_text = "\n\n".join(sample_parts)

    system_prompt = """
You are a senior code auditor and debugging engineer.
Return ONLY valid JSON.
Do not wrap the JSON in markdown.

Schema:
{
  "summary": "string",
  "risk_score": 0,
  "top_risks": [
    {
      "title": "string",
      "severity": "critical|high|medium|low",
      "file": "string",
      "why_it_matters": "string",
      "fix": "string"
    }
  ],
  "quick_fixes": ["string"],
  "vibe_coder_explanation": "string",
  "merge_recommendation": "approve|caution|block"
}
"""

    user_prompt = f"""
Target: {context_name}

Focus:
{focus}

Scanner findings:
{findings_text}

Relevant code samples:
{sample_text}

Tasks:
1. Summarize the real issues.
2. Prioritize the top risks.
3. Explain them in plain English for non-developers.
4. Suggest practical fixes.
5. Give a merge recommendation: approve, caution, or block.
"""

    try:
        result = client.llm.chat(
            model=og.TEE_LLM.GPT_4O,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=1600,
            temperature=0.1,
            x402_settlement_mode=og.x402SettlementMode.SETTLE_BATCH,
        )
        raw = result.chat_output["content"]
        payment_hash = getattr(result, "payment_hash", None)

    except Exception as e:
        fallback = make_human_fallback_summary("repo", findings)
        fallback["vibe_coder_explanation"] = (
            "AI explanation is temporarily unavailable in this environment, but the scanner findings below are still valid."
        )
        fallback["debug_error"] = str(e)
        return fallback

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and end > start:
            parsed = json.loads(raw[start:end + 1])
        else:
            parsed = {
                "summary": raw,
                "risk_score": 0,
                "top_risks": [],
                "quick_fixes": [],
                "vibe_coder_explanation": raw,
                "merge_recommendation": "caution",
            }

    parsed["payment_hash"] = payment_hash
    return parsed


def detect_snippet_language(code: str, provided_language: Optional[str] = None) -> str:
    stripped = code.strip()
    code_lower = stripped.lower()

    # Respect explicit user choice unless it's auto
    if provided_language and provided_language.lower() not in ["", "auto"]:
        return provided_language.lower()

    # Solidity first
    solidity_signals = [
        "pragma solidity",
        "contract ",
        "interface ",
        "library ",
        "msg.sender",
        "msg.value",
        "uint256",
        "mapping(",
        "mapping (",
        "event ",
        "modifier ",
        "address(",
        "external ",
        "public ",
        "private ",
        "internal ",
    ]
    if any(signal in code_lower for signal in solidity_signals):
        return "solidity"

    # JSX / TSX
    if "<" in stripped and ">" in stripped and ("return (" in stripped or "return <" in stripped):
        tsx_signals = ["interface ", "type ", ": string", ": number", ": boolean", "useState<", "React."]
        if any(signal in stripped for signal in tsx_signals):
            return "tsx"
        return "jsx"

        # JavaScript / TypeScript should be checked before Python
    js_signals = [
        "const ",
        "let ",
        "var ",
        "function ",
        "=>",
        "require(",
        "module.exports",
        "exports.",
        "console.log(",
        "document.",
        "window.",
        "express(",
        "app.get(",
        "app.post(",
        "res.send(",
        "res.json(",
        "new regexp(",
    ]
    if any(signal.lower() in code_lower for signal in js_signals):
        ts_signals = [
            "interface ",
            "type ",
            ": string",
            ": number",
            ": boolean",
            "implements ",
            " as ",
            ": any",
            ": unknown",
            "enum ",
            "<string>",
            "<number>",
        ]
        if any(signal in stripped for signal in ts_signals):
            return "typescript"
        return "javascript"

    # JSON
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        return "json"

    # Python after JS
    python_signals = [
        "import ",
        "from ",
        "def ",
        "print(",
        "except ",
        "elif ",
        "self.",
        "class ",
        "lambda ",
        "__name__",
        "none",
        "true",
        "false",
    ]
    if any(signal in code_lower for signal in python_signals):
        return "python"

    return "javascript"


def write_snippet_to_temp(code: str, language: str, temp_dir: str) -> str:
    ext_map = {
        "python": "snippet.py",
        "javascript": "snippet.js",
        "typescript": "snippet.ts",
        "tsx": "snippet.tsx",
        "jsx": "snippet.jsx",
        "json": "snippet.json",
        "solidity": "snippet.sol",
    }
    filename = ext_map.get(language.lower(), "snippet.txt")
    path = os.path.join(temp_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code)
    return path


def detect_main_language(paths: List[str]) -> str:
    counts = {"python": 0, "javascript": 0, "typescript": 0}
    for path in paths:
        if path.endswith(".py"):
            counts["python"] += 1
        elif path.endswith((".js", ".jsx")):
            counts["javascript"] += 1
        elif path.endswith((".ts", ".tsx")):
            counts["typescript"] += 1
    return max(counts, key=counts.get) if paths else "unknown"

def heuristic_snippet_findings(code: str, language: str) -> List[Dict[str, Any]]:
    findings = []
    lower_code = code.lower()

    if language.lower() == "python":
        uses_threads = "threading.thread" in lower_code or "import threading" in lower_code
        uses_lock = (
            "threading.lock" in lower_code
            or ".acquire(" in lower_code
            or ".release(" in lower_code
            or "with lock" in lower_code
        )
        mutates_shared_state = any(token in lower_code for token in [
            ".append(",
            ".pop(",
            ".remove(",
            ".withdraw(",
            ".deposit(",
            ".transfer(",
            "balances[",
            "self.",
        ])

        if uses_threads and mutates_shared_state and not uses_lock:
            findings.append({
                "tool": "heuristic",
                "severity": "high",
                "title": "Possible race condition from shared mutable state",
                "file": "./snippet.py",
                "line": 1,
                "description": "The code appears to modify shared state across multiple threads without visible locking or synchronization.",
                "fix_hint": "Protect shared state with threading.Lock or redesign access so only one thread mutates the shared object at a time."
            })

        if "eval(" in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "high",
                "title": "Use of eval()",
                "file": "./snippet.py",
                "line": 1,
                "description": "eval() can execute arbitrary code and is dangerous with untrusted input.",
                "fix_hint": "Avoid eval() and use safer parsing such as ast.literal_eval where appropriate."
            })

        if "exec(" in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "high",
                "title": "Use of exec()",
                "file": "./snippet.py",
                "line": 1,
                "description": "exec() can execute arbitrary code and is dangerous with untrusted input.",
                "fix_hint": "Avoid exec() and replace it with explicit logic."
            })

        if "except:" in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "medium",
                "title": "Broad bare except detected",
                "file": "./snippet.py",
                "line": 1,
                "description": "A bare except can hide important runtime errors and make debugging harder.",
                "fix_hint": "Catch specific exception types instead of using a bare except."
            })

    if language.lower() in ["javascript", "typescript", "jsx", "tsx"]:
        if "eval(" in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "high",
                "title": "Use of eval()",
                "file": "./snippet.js",
                "line": 1,
                "description": "eval() is dangerous and can execute arbitrary code.",
                "fix_hint": "Replace eval() with safer parsing or explicit logic."
            })

        if "innerhtml" in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "medium",
                "title": "Potential unsafe innerHTML usage",
                "file": "./snippet.js",
                "line": 1,
                "description": "Direct innerHTML assignment can introduce XSS risk if content is not sanitized.",
                "fix_hint": "Sanitize the content or use safer DOM APIs."
            })

        if "algorithm: 'none'" in lower_code or 'algorithm: "none"' in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "high",
                "title": "Insecure JWT algorithm 'none'",
                "file": "./snippet.js",
                "line": 1,
                "description": "Using the 'none' JWT algorithm can allow authentication bypass if tokens are accepted without signature verification.",
                "fix_hint": "Use a secure signing algorithm such as HS256 or RS256 and verify tokens properly."
            })

        if (
            "secret_key" in lower_code
            or "const secret" in lower_code
            or "const secret_key" in lower_code
            or "jwt.sign(" in lower_code and ("secret" in lower_code)
        ):
            findings.append({
                "tool": "heuristic",
                "severity": "medium",
                "title": "Possible hardcoded JWT secret",
                "file": "./snippet.js",
                "line": 1,
                "description": "A hardcoded secret in source code can be exposed and reused by attackers.",
                "fix_hint": "Move secrets to environment variables or a secure secret manager."
            })

        if "new regexp(" in lower_code and ("req.query" in lower_code or "req.body" in lower_code or "pattern" in lower_code):
            findings.append({
                "tool": "heuristic",
                "severity": "high",
                "title": "Possible user-controlled regular expression (ReDoS risk)",
                "file": "./snippet.js",
                "line": 1,
                "description": "Creating a RegExp from user input can lead to catastrophic backtracking and denial of service.",
                "fix_hint": "Do not build regex patterns directly from untrusted input. Validate or constrain allowed patterns."
            })

        if (
            ("for (let key in" in lower_code or "for (const key in" in lower_code or "for (var key in" in lower_code)
            and ("[key]" in lower_code)
        ):
            findings.append({
                "tool": "heuristic",
                "severity": "high",
                "title": "Possible prototype pollution via dynamic object assignment",
                "file": "./snippet.js",
                "line": 1,
                "description": "Assigning user-controlled keys into objects without validation can allow dangerous keys like __proto__ or constructor.",
                "fix_hint": "Validate allowed keys explicitly and block dangerous property names such as __proto__, prototype, and constructor."
            })

        if "console.log" in lower_code and ("req" in lower_code or "headers" in lower_code):
            findings.append({
                "tool": "heuristic",
                "severity": "medium",
                "title": "Potential sensitive request logging",
                "file": "./snippet.js",
                "line": 1,
                "description": "Logging full request objects or headers can expose tokens, cookies, and personal data.",
                "fix_hint": "Log only safe, minimal fields and never dump full request objects in production."
            })

    if language.lower() == "solidity":
        if ".call{value:" in lower_code or ".call.value(" in lower_code:
            if "balances[msg.sender] -=" in lower_code or "balances[msg.sender]-=" in lower_code:
                call_pos = lower_code.find(".call{value:")
                if call_pos == -1:
                    call_pos = lower_code.find(".call.value(")

                balance_update_pos = lower_code.find("balances[msg.sender] -=")
                if balance_update_pos == -1:
                    balance_update_pos = lower_code.find("balances[msg.sender]-=")

                if call_pos != -1 and balance_update_pos != -1 and call_pos < balance_update_pos:
                    findings.append({
                        "tool": "heuristic",
                        "severity": "high",
                        "title": "Possible reentrancy vulnerability",
                        "file": "./snippet.sol",
                        "line": 1,
                        "description": "The contract performs an external value transfer before updating internal state, which can enable reentrancy attacks.",
                        "fix_hint": "Update state before external calls and consider using ReentrancyGuard."
                    })

        if "tx.origin" in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "medium",
                "title": "Use of tx.origin for authorization",
                "file": "./snippet.sol",
                "line": 1,
                "description": "Using tx.origin for authorization can be unsafe and may allow phishing-style attacks.",
                "fix_hint": "Use msg.sender for authorization checks instead of tx.origin."
            })

        if "selfdestruct(" in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "medium",
                "title": "Use of selfdestruct",
                "file": "./snippet.sol",
                "line": 1,
                "description": "selfdestruct can have dangerous side effects and should be used with care.",
                "fix_hint": "Avoid selfdestruct unless there is a strong and well-reviewed reason."
            })

        if ".delegatecall(" in lower_code:
            findings.append({
                "tool": "heuristic",
                "severity": "high",
                "title": "Use of delegatecall",
                "file": "./snippet.sol",
                "line": 1,
                "description": "delegatecall can execute code in the caller's context and is dangerous if not tightly controlled.",
                "fix_hint": "Avoid delegatecall unless absolutely necessary and audit all call targets carefully."
            })

    return findings    


def classify_pr_findings(findings: List[Dict[str, Any]], pr_files: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    changed_paths = set()
    for item in pr_files:
        filename = item.get("filename", "")
        if filename:
            changed_paths.add(filename)
            changed_paths.add(f"./{filename}")

    touched = []
    existing = []

    for finding in findings:
        finding_file = (finding.get("file") or "").strip()

        if finding_file in changed_paths:
            enriched = dict(finding)
            enriched["pr_relation"] = "touched_by_pr"
            touched.append(enriched)
        else:
            enriched = dict(finding)
            enriched["pr_relation"] = "existing_repo_issue"
            existing.append(enriched)

    return {
        "touched_by_pr": touched,
        "existing_repo_issues": existing,
    }

def severity_weight(severity: str) -> int:
    severity = (severity or "").lower()
    if severity == "critical":
        return 40
    if severity == "high":
        return 25
    if severity == "medium":
        return 12
    if severity == "low":
        return 5
    return 0


def calculate_risk_score(findings: List[Dict[str, Any]], mode: str = "repo") -> int:
    if not findings:
        return 5 if mode == "pr" else 0

    score = sum(severity_weight(item.get("severity", "")) for item in findings)

    combined_titles = " || ".join((item.get("title") or "").lower() for item in findings)
    combined_desc = " || ".join((item.get("description") or "").lower() for item in findings)
    combined = f"{combined_titles} || {combined_desc}"

    # special boosts for higher-impact vulnerability classes
    if "reentrancy" in combined:
        score += 35
    if "delegatecall" in combined:
        score += 30
    if "tx.origin" in combined:
        score += 20
    if "algorithm 'none'" in combined or "jwt algorithm" in combined:
        score += 20
    if "sql injection" in combined:
        score += 20
    if "command injection" in combined or "shell=true" in combined or "os.system" in combined:
        score += 20
    if "prototype pollution" in combined:
        score += 18
    if "redos" in combined or "regular expression" in combined:
        score += 15
    if "cve-" in combined:
        score += 15

    if mode == "snippet":
        score += 5
    elif mode == "repo":
        score += 10
    elif mode == "pr":
        score += 8

    return min(score, 100)


def group_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    for item in findings:
        sev = (item.get("severity") or "low").lower()
        if sev not in grouped:
            sev = "low"
        grouped[sev].append(item)

    return grouped


def build_status_label(mode: str, risk_score: int, pr_has_touched_findings: bool = False) -> str:
    if mode == "pr":
        if pr_has_touched_findings and risk_score >= 40:
            return "Caution"
        if pr_has_touched_findings:
            return "Review Needed"
        if risk_score >= 40:
            return "Approve With Existing Risks"
        return "Approve"

    if mode == "repo":
        if risk_score >= 70:
            return "Critical"
        if risk_score >= 35:
            return "Needs Attention"
        if risk_score > 0:
            return "Monitor"
        return "Healthy"

    if mode == "snippet":
        if risk_score >= 70:
            return "High Risk"
        if risk_score >= 35:
            return "Moderate Risk"
        if risk_score > 0:
            return "Low Risk"
        return "Looks Safe"

    return "Unknown"

def generate_recommended_actions(findings: List[Dict[str, Any]], mode: str = "repo") -> List[str]:
    actions = []

    titles = " || ".join((item.get("title") or "").lower() for item in findings)
    descriptions = " || ".join((item.get("description") or "").lower() for item in findings)

    combined = f"{titles} || {descriptions}"

    if "jwt algorithm" in combined or "algorithm 'none'" in combined:
        actions.append("Replace JWT 'none' with a secure signing algorithm such as HS256 or RS256.")

    if "hardcoded jwt secret" in combined or "hardcoded password" in combined or "secret" in combined:
        actions.append("Move hardcoded secrets out of source code and into environment variables or a secret manager.")

    if "prototype pollution" in combined:
        actions.append("Validate object keys explicitly and block dangerous keys such as __proto__, constructor, and prototype.")

    if "regular expression" in combined or "redos" in combined:
        actions.append("Do not build regular expressions directly from untrusted input; validate or constrain allowed patterns.")

    if "request logging" in combined or "headers" in combined:
        actions.append("Avoid logging full request objects or headers in production; log only safe, minimal fields.")

    if "reentrancy" in combined:
        actions.append("Update contract state before external calls and consider using ReentrancyGuard.")

    if "delegatecall" in combined:
        actions.append("Review delegatecall usage carefully and avoid it unless absolutely necessary.")

    if "tx.origin" in combined:
        actions.append("Replace tx.origin authorization checks with msg.sender.")

    if "sql injection" in combined:
        actions.append("Use parameterized queries instead of string interpolation when building SQL statements.")

    if "shell=true" in combined or "os.system" in combined or "command injection" in combined:
        actions.append("Avoid shell execution with untrusted input; use safer subprocess patterns without shell=True.")

    if "md5" in combined:
        actions.append("Replace MD5 with a stronger hash such as SHA-256 unless there is a non-security-specific reason.")

    if "dockerfile" in combined or "image user should not be 'root'" in combined:
        actions.append("Run the container as a non-root user in the Dockerfile.")

    if "cve-" in combined:
        actions.append("Upgrade vulnerable dependencies to the fixed versions listed in the findings.")

    if not actions:
        if mode == "snippet":
            actions = [
                "Fix the highest-severity findings first.",
                "Re-run the snippet after making changes.",
            ]
        elif mode == "pr":
            actions = [
                "Review findings tied to files changed by this PR first.",
                "Track unrelated existing repo issues separately.",
            ]
        else:
            actions = [
                "Review high-severity findings first.",
                "Triage low-priority findings separately.",
            ]

    # remove duplicates while preserving order
    deduped = []
    seen = set()
    for action in actions:
        if action not in seen:
            seen.add(action)
            deduped.append(action)

    return deduped[:6]

def make_human_fallback_summary(mode: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    risk_score = calculate_risk_score(findings, mode=mode)
    grouped = group_findings_by_severity(findings)

    if mode == "repo":
        summary = "Repository scan completed. AI explanation is temporarily unavailable, but the scanner findings below are still valid."
        status = build_status_label("repo", risk_score)
    elif mode == "snippet":
        summary = "Snippet scan completed. AI explanation is temporarily unavailable, but the scanner findings below are still valid."
        status = build_status_label("snippet", risk_score)
    else:
        summary = "Scan completed. AI explanation is temporarily unavailable, but the scanner findings below are still valid."
        status = "Caution"

    top_risks = findings[:5]

    return {
        "summary": summary,
        "risk_score": risk_score,
        "status_label": status,
        "top_risks": [
            {
                "title": item.get("title", "Finding"),
                "severity": item.get("severity", "low"),
                "file": item.get("file", ""),
                "why_it_matters": item.get("description", "Scanner detected a possible issue."),
                "fix": item.get("fix_hint") or "Review and remediate this issue.",
            }
            for item in top_risks
        ],
        "quick_fixes": generate_recommended_actions(findings, mode=mode),
        "vibe_coder_explanation": "AI explanation is temporarily unavailable, but the scanner findings below are still valid.",
        "merge_recommendation": "caution",
        "payment_hash": None,
        "severity_groups": grouped,
    }

@app.get("/")
def root():
    return FileResponse(INDEX_FILE)


@app.get("/login/github")
def login_github(request: Request):
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Missing GitHub OAuth credentials in .env")

    redirect_uri = f"{BASE_URL}/auth/github/callback"
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "repo read:user user:email",
    }
    url = "https://github.com/login/oauth/authorize"
    query = "&".join([f"{k}={requests.utils.quote(str(v))}" for k, v in params.items()])
    return RedirectResponse(url=f"{url}?{query}")


@app.get("/auth/github/callback")
def github_callback(request: Request, code: str):
    redirect_uri = f"{BASE_URL}/auth/github/callback"

    response = requests.post(
        "https://github.com/login/oauth/access_token",
        headers={"Accept": "application/json"},
        data={
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri,
        },
        timeout=60,
    )
    data = response.json()

    access_token = data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Failed to get GitHub access token")

    request.session["github_access_token"] = access_token

    user_data = github_get("https://api.github.com/user", access_token)
    request.session["github_user"] = {
        "login": user_data.get("login"),
        "name": user_data.get("name"),
        "avatar_url": user_data.get("avatar_url"),
    }

    return RedirectResponse(url="/")


@app.get("/api/session")
def session_info(request: Request):
    user = request.session.get("github_user")
    return {
        "connected": bool(user),
        "user": user,
    }

@app.get("/api/repos")
def list_connected_repos(request: Request):
    token = get_user_token(request)
    repos = github_get_user_repos(token)
    return {"repos": repos}


@app.get("/api/repos/{owner}/{repo}/pulls")
def list_repo_pulls(owner: str, repo: str, request: Request):
    token = get_user_token(request)
    pulls = github_paginated_get(
        f"https://api.github.com/repos/{owner}/{repo}/pulls",
        token,
        per_page=100,
        max_pages=3,
    )

    cleaned = []
    for pr in pulls:
        cleaned.append({
            "number": pr.get("number"),
            "title": pr.get("title"),
            "state": pr.get("state"),
            "head_ref": pr.get("head", {}).get("ref", ""),
            "base_ref": pr.get("base", {}).get("ref", ""),
        })

    return {"pulls": cleaned}

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return JSONResponse({"ok": True})


@app.get("/api/health")
def health():
    return {"ok": True}


@app.post("/api/repo-scan")
def repo_scan(payload: RepoScanRequest, request: Request):
    token = get_user_token(request)
    owner = payload.owner.strip()
    repo = payload.repo.strip()
    branch = payload.branch.strip() if payload.branch else ""

    if not owner or not repo:
        raise HTTPException(status_code=400, detail="Missing owner or repo")

    if not branch:
        branch = get_default_branch(token, owner, repo)

    temp_dir = tempfile.mkdtemp(prefix="repo_scan_")
    try:
        written_files = build_local_repo_from_github(
            token=token,
            owner=owner,
            repo=repo,
            branch=branch,
            target_dir=temp_dir,
            pr_number=payload.pr_number,
        )

        if not written_files:
            raise HTTPException(status_code=400, detail="No readable files were downloaded")

        semgrep_data = run_semgrep(temp_dir)
        bandit_data = run_bandit(temp_dir)
        trivy_data = run_trivy(temp_dir)

        findings = normalize_all(semgrep_data, bandit_data, trivy_data)

        pr_files = []
        classified_findings = {
            "touched_by_pr": [],
            "existing_repo_issues": [],
        }

        if payload.pr_number:
            pr_files = get_pr_files(token, owner, repo, payload.pr_number)
            classified_findings = classify_pr_findings(findings, pr_files)

        sample_files = {}
        for rel_path in written_files[:8]:
            full_path = os.path.join(temp_dir, rel_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        sample_files[rel_path] = f.read()
                except Exception:
                    pass

        context = f"{owner}/{repo}:{branch}"
        if payload.pr_number:
            context += f" PR#{payload.pr_number}"

        scanner_counts = {
            "semgrep": len(normalize_semgrep(semgrep_data)),
            "bandit": len(normalize_bandit(bandit_data)),
            "trivy": len(normalize_trivy(trivy_data)),
            "total": len(findings),
        }

        if payload.pr_number:
            changed_files = [item.get("filename", "") for item in pr_files]

            evidence_payload = build_pr_evidence_payload(
                repo_name=f"{owner}/{repo}:{branch}",
                pr_number=payload.pr_number,
                changed_files=changed_files,
                touched_findings=classified_findings["touched_by_pr"],
                existing_findings=classified_findings["existing_repo_issues"],
                scanner_counts=scanner_counts,
            )
            ai_summary = generate_verified_reasoning("pr", evidence_payload)
        else:
            evidence_payload = build_repo_evidence_payload(
                repo_name=f"{owner}/{repo}:{branch}",
                findings=findings,
                scanner_counts=scanner_counts,
                sample_files=sample_files,
            )
            ai_summary = generate_verified_reasoning("repo", evidence_payload)

        mode = "pr" if payload.pr_number else "repo"

        if payload.pr_number:
            touched_count = len(classified_findings["touched_by_pr"])
            existing_count = len(classified_findings["existing_repo_issues"])
            pr_relevant_findings = (
                classified_findings["touched_by_pr"]
                if classified_findings["touched_by_pr"]
                else classified_findings["existing_repo_issues"]
)

            if ai_summary.get("verification_mode") == "fallback":
                risk_score = calculate_risk_score(pr_relevant_findings, mode="pr")
                status_label = build_status_label("pr", risk_score, pr_has_touched_findings=touched_count > 0)

                if touched_count > 0:
                    ai_summary["summary"] = (
                        f"PR audit completed. {touched_count} finding(s) are tied to files changed by this PR, "
                        f"and {existing_count} additional existing repo issue(s) were also surfaced."
                    )
                    ai_summary["quick_fixes"] = generate_recommended_actions(pr_relevant_findings, mode="pr")
                else:
                    ai_summary["summary"] = (
                        f"PR audit completed. No scanner findings were directly tied to files changed by this PR. "
                        f"{existing_count} existing repo issue(s) were surfaced separately."
                    )
                ai_summary["quick_fixes"] = generate_recommended_actions(findings, mode="pr")

                ai_summary["risk_score"] = risk_score
                ai_summary["status_label"] = status_label
                ai_summary["merge_recommendation"] = status_label
                ai_summary["top_risks"] = [
                    {
                        "title": item.get("title", "Finding"),
                        "severity": item.get("severity", "low"),
                        "file": item.get("file", ""),
                        "why_it_matters": item.get("description", "Scanner detected a possible issue."),
                        "fix": item.get("fix_hint") or "Review and remediate this issue.",
                    }
                    for item in pr_relevant_findings[:5]
                ]
                ai_summary["severity_groups"] = group_findings_by_severity(pr_relevant_findings)
                ai_summary["user_explanation"] = (
                    "AI reasoning is temporarily unavailable, but the PR findings below are still valid and can be reviewed."
                )
            else:
                ai_summary["severity_groups"] = group_findings_by_severity(pr_relevant_findings)
                ai_summary["quick_fixes"] = ai_summary.get("recommended_actions", [])
            touched_count = len(classified_findings["touched_by_pr"])
            existing_count = len(classified_findings["existing_repo_issues"])

            pr_relevant_findings = classified_findings["touched_by_pr"]
            risk_score = calculate_risk_score(pr_relevant_findings if pr_relevant_findings else findings, mode="pr")
            status_label = build_status_label("pr", risk_score, pr_has_touched_findings=touched_count > 0)

            if touched_count > 0:
                ai_summary["summary"] = (
                    f"PR audit completed. {touched_count} finding(s) are tied to files changed by this PR, "
                    f"and {existing_count} additional existing repo issue(s) were also surfaced."
                )
                ai_summary["quick_fixes"] = [
                    "Review findings tied to files changed by this PR first.",
                    "Fix high-severity PR-related findings before merge.",
                    "Track unrelated existing repo issues separately.",
                ]
            else:
                ai_summary["summary"] = (
                    f"PR audit completed. No scanner findings were directly tied to files changed by this PR. "
                    f"{existing_count} existing repo issue(s) were surfaced separately."
                )
                ai_summary["quick_fixes"] = [
                    "This PR does not appear to introduce scanner-detected issues.",
                    "Track existing repo issues separately.",
                    "Merge may proceed if code review and tests are otherwise satisfactory.",
                ]

            ai_summary["risk_score"] = risk_score
            ai_summary["status_label"] = status_label
            ai_summary["merge_recommendation"] = status_label
            ai_summary["severity_groups"] = group_findings_by_severity
            ai_summary["quick_fixes"] = generate_recommended_actions(
                pr_relevant_findings if pr_relevant_findings else findings,
                mode="pr"
            )

        if not payload.pr_number:
            if ai_summary.get("verification_mode") == "fallback":
                ai_summary["risk_score"] = calculate_risk_score(findings, mode="repo")
                ai_summary["status_label"] = build_status_label("repo", ai_summary["risk_score"])
                ai_summary["severity_groups"] = group_findings_by_severity(findings)
                ai_summary["quick_fixes"] = generate_recommended_actions(findings, mode="repo")
            else:
                ai_summary["severity_groups"] = group_findings_by_severity(findings)
                ai_summary["quick_fixes"] = ai_summary.get("recommended_actions", [])

        return {
            "repo": f"{owner}/{repo}:{branch}",
            "pr_number": payload.pr_number,
            "files_downloaded": len(written_files),
            "detected_language": detect_main_language(written_files),
            "scanner_counts": scanner_counts,
            "top_findings": findings[:30],
            "pr_changed_files": [item.get("filename", "") for item in pr_files] if payload.pr_number else [],
            "classified_findings": classified_findings,
            "ai_summary": ai_summary,
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/snippet-scan")
def snippet_scan(payload: SnippetScanRequest):
    if not payload.code.strip():
        raise HTTPException(status_code=400, detail="Code is required")

    temp_dir = tempfile.mkdtemp(prefix="snippet_scan_")
    try:
        detected_language = detect_snippet_language(payload.code, payload.language)
        snippet_path = write_snippet_to_temp(payload.code, detected_language, temp_dir)

        semgrep_data = run_semgrep(temp_dir)
        bandit_data = run_bandit(temp_dir) if detected_language == "python" else {"results": []}
        trivy_data = {"Results": []}

        findings = normalize_all(semgrep_data, bandit_data, trivy_data)

        if not findings:
            findings = heuristic_snippet_findings(payload.code, detected_language)

        evidence_payload = build_snippet_evidence_payload(
            code=payload.code,
            language=detected_language,
            findings=findings,
            error_message=payload.error_message or "",
        )

        ai_summary = generate_verified_reasoning("snippet", evidence_payload)

        if ai_summary.get("verification_mode") == "fallback":
            ai_summary["risk_score"] = calculate_risk_score(findings, mode="snippet")
            ai_summary["status_label"] = build_status_label("snippet", ai_summary["risk_score"])
            ai_summary["severity_groups"] = group_findings_by_severity(findings)
            ai_summary["quick_fixes"] = generate_recommended_actions(findings, mode="snippet")
        else:
            ai_summary["severity_groups"] = group_findings_by_severity(findings)
            ai_summary["quick_fixes"] = ai_summary.get("recommended_actions", [])

        if ai_summary.get("summary", "").startswith("Repository scan completed."):
            ai_summary["summary"] = "Snippet scan completed. AI explanation is temporarily unavailable, but the scanner findings below are still valid."

        if ai_summary.get("vibe_coder_explanation", "").startswith("The code scanners worked, but the AI explanation step could not reach OpenGradient"):
            ai_summary["vibe_coder_explanation"] = (
                "AI explanation is temporarily unavailable, but the scanner findings below are still valid."
            )

        return {
            "language": detected_language,
            "scanner_counts": {
                "semgrep": len(normalize_semgrep(semgrep_data)),
                "bandit": len(normalize_bandit(bandit_data)),
                "total": len(findings),
            },
            "top_findings": findings[:20],
            "ai_summary": ai_summary,
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)