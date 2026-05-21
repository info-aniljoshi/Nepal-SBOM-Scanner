import os
import json
import aiohttp
import re
import logging
from typing import Optional, Dict, Any, Union
from core.database import get_cached_explanation, save_cached_explanation

logger = logging.getLogger("nepal-sbom-ai")

async def call_llm(system_prompt: str, user_prompt: str) -> str:
    """Expert Note: Implemented robust LLM caller with multi-provider support and timeouts"""
    groq_key = os.environ.get("GROQ_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")
    
    if groq_key:
        api_url = "https://api.groq.com/openai/v1/chat/completions"
        api_key = groq_key
        model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
    elif openai_key:
        api_url = "https://api.openai.com/v1/chat/completions"
        api_key = openai_key
        model = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
    else:
        return "ERROR: AI providers not configured. Please set GROQ_API_KEY or OPENAI_API_KEY."

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
        "temperature": 0.1, # Low temperature for more deterministic security advice
        "max_tokens": 800
    }

    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(api_url, headers=headers, json=payload) as resp:
                if resp.status != 200:
                    err_body = await resp.text()
                    logger.error(f"LLM API Error {resp.status}: {err_body}")
                    return f"API Error: {resp.status}"
                data = await resp.json()
                return str(data["choices"][0]["message"]["content"])
    except Exception as e:
        logger.error(f"LLM request failed: {e}")
        return f"Request failed: {str(e)}"

async def get_remediation(cve_id: str, package_name: str, version: str, severity: str, summary: str) -> str:
    """Get AI-powered remediation advice with local caching"""
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
VERIFICATION: How to verify the secret is removed from version control."""
    else:
        system_prompt = "You are a Security Research Assistant. Provide a concise 3-line remediation for a vulnerability."
        user_prompt = f"""Vulnerability: {cve_id}
Package: {package_name}@{version}
Severity: {severity}
Summary: {summary}

Provide remediation in exactly 3 lines:
THREAT: Brief risk explanation.
FIX: Exact version upgrade command (e.g., `pip install ...`).
VERIFICATION: How to check the fix works."""
    
    explanation = await call_llm(system_prompt, user_prompt)
    
    if not explanation.startswith(("ERROR:", "API Error:", "Request failed:")):
        save_cached_explanation(cve_id, explanation)
        
    return explanation

async def get_executive_summary(vulns_json: str) -> str:
    """Generate high-level risk assessment for stakeholders"""
    system_prompt = "You are a CISO writing a board-level risk summary. Focus on business impact."
    user_prompt = f"""Vulnerability Data:
{vulns_json}

Write 2 paragraphs:
1. Current risk level and top 3 concerns.
2. Recommended actions with timeline.
No jargon. No CVE IDs."""
    
    return await call_llm(system_prompt, user_prompt)

async def get_structured_fix(cve_id: str, package_name: str, version: str, severity: str, summary: str) -> Dict[str, Optional[str]]:
    """Expert Note: Robust JSON extraction using regex to handle LLM markdown noise"""
    system_prompt = "You are a security automation tool. Respond ONLY with a raw JSON object."
    user_prompt = f"""Extract fix for {package_name}@{version} ({cve_id}).
Required JSON: {{"package": "string", "version": "string"}}
Description: {summary}"""
    
    resp = await call_llm(system_prompt, user_prompt)
    try:
        # Regex to extract JSON from markdown or noise
        match = re.search(r'\{.*\}', resp, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        return json.loads(resp)
    except Exception as e:
        logger.warning(f"Failed to parse LLM response as JSON: {e} | Raw: {resp[:100]}")
        return {"package": package_name, "version": None}
