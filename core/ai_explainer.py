import os
import json
import aiohttp
from core.database import get_cached_explanation, save_cached_explanation

async def call_llm(system_prompt: str, user_prompt: str) -> str:
    groq_key = os.environ.get("GROQ_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")
    
    if groq_key:
        api_url = "https://api.groq.com/openai/v1/chat/completions"
        api_key = groq_key
        model = "llama-3.1-8b-instant"
    elif openai_key:
        api_url = "https://api.openai.com/v1/chat/completions"
        api_key = openai_key
        model = "gpt-3.5-turbo"
    else:
        return "ERROR: No GROQ_API_KEY or OPENAI_API_KEY found in environment variables. Please add one to use the AI features."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 500
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(api_url, headers=headers, json=payload) as resp:
                if resp.status != 200:
                    err = await resp.text()
                    return f"API Error: {resp.status} - {err}"
                data = await resp.json()
                return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Request failed: {str(e)}"

async def get_remediation(cve_id: str, package_name: str, version: str, severity: str, summary: str) -> str:
    cached = get_cached_explanation(cve_id)
    if cached:
        return cached

    if cve_id.startswith("CODE-"):
        system_prompt = "You are a Senior Security Engineer. Provide a concise 3-line fix for a source code security flaw."
        user_prompt = f"""Issue: {summary}
Severity: {severity}
Description: Hardcoded secret or insecure pattern found in source code.

Provide remediation in exactly 3 lines:
THREAT: Explain the risk of this hardcoded secret.
FIX: Recommend moving this secret to an environment variable (.env) and using `os.getenv()`.
VERIFICATION: How to verify the secret is removed from version control.
"""
    else:
        system_prompt = "You are a Security Research Assistant. Provide a concise 3-line remediation for a vulnerability."
        user_prompt = f"""Vulnerability: {cve_id}
Package: {package_name}@{version}
Severity: {severity}
Summary: {summary}

Provide remediation in exactly 3 lines:
THREAT: Brief risk explanation.
FIX: Exact version upgrade command (e.g., `pip install ...`).
VERIFICATION: How to check the fix works.
"""
    
    explanation = await call_llm(system_prompt, user_prompt)
    
    if not explanation.startswith("ERROR:") and not explanation.startswith("API Error:"):
        save_cached_explanation(cve_id, explanation)
        
    return explanation

async def get_executive_summary(vulns_json: str) -> str:
    system_prompt = "You are a CISO writing a board-level risk summary."
    user_prompt = f"""A software project has the following vulnerabilities:
{vulns_json}

Write 2 paragraphs:
1. Current risk level and top 3 concerns.
2. Recommended actions with timeline (immediate / this week / this month).

Use plain English. No jargon. No CVE IDs. Focus on business impact.
"""
    
    return await call_llm(system_prompt, user_prompt)

async def get_structured_fix(cve_id: str, package_name: str, version: str, severity: str, summary: str) -> dict:
    """Ask LLM for a structured fix (package and target version)"""
    system_prompt = "You are a tool that extracts structured fix information. Respond ONLY with a JSON object."
    user_prompt = f"""CVE: {cve_id}
Package: {package_name}@{version}
Severity: {severity}
Description: {summary}

What is the exact package name and the minimum safe version to upgrade to?
Respond ONLY with a JSON object like this: {{"package": "name", "version": "1.2.3"}}
"""
    
    resp = await call_llm(system_prompt, user_prompt)
    try:
        # Simple cleanup in case LLM adds markdown blocks
        json_str = resp.strip().strip('```json').strip('```').strip()
        return json.loads(json_str)
    except:
        return {"package": package_name, "version": None}
