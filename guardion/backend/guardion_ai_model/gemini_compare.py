"""
Guardion AI — Gemini Comparison Module
=======================================
Sends a prompt to the Gemini API for classification, then compares
the Gemini result with the local ML model's prediction side by side.

The Gemini call uses the same five security categories as the local model:
  safe | pii_leak | credential_leak | financial_data | secret_code

Output includes a combined decision (ALLOW / WARN / BLOCK).
"""

import json
import re
import asyncio
import sys
import os
from typing import Optional

import google.generativeai as genai

from guardion_ai_model.inference import analyze_prompt as local_analyze

# Import shared cache & rate limiter (works when running inside the backend)
try:
    from app.services.gemini_cache import gemini_cache, gemini_rate_limiter
    _HAS_CACHE = True
except ImportError:
    _HAS_CACHE = False


# ──────────────────── Gemini Configuration ────────────────────

_configured = False


def _ensure_gemini_configured(api_key: str) -> bool:
    """Configure the Gemini SDK with the provided API key."""
    global _configured
    if _configured:
        return True
    if api_key and api_key != "your_gemini_api_key_here":
        genai.configure(api_key=api_key)
        _configured = True
        return True
    return False


# ──────────────────── Gemini Prompt Classification ────────────────────

CLASSIFICATION_PROMPT = """You are a calibrated cybersecurity classifier. Assign probability scores to EACH category for the user prompt below.

Categories:
- safe: Normal coding/general question, no sensitive data
- pii_leak: Personal info (email, phone, SSN, name+address, DOB)
- credential_leak: API keys, passwords, tokens, connection strings
- financial_data: Credit card numbers, bank accounts, routing numbers
- secret_code: Private keys (PEM, SSH, PGP), encryption secrets

Rules:
- All 5 scores MUST sum to exactly 1.0
- Use realistic probabilities (avoid 0.0 and 1.0 extremes)
- Even for obvious cases, assign the top class 0.75-0.90 max and spread residual across others
- "prediction" = the category with the highest score
- "confidence" = that highest score

Respond with ONLY valid JSON (no markdown):
{{
    "prediction": "<top category>",
    "confidence": <highest score>,
    "all_scores": {{"safe": <float>, "pii_leak": <float>, "credential_leak": <float>, "financial_data": <float>, "secret_code": <float>}},
    "explanation": "<one sentence>"
}}

User prompt:
\"\"\"{prompt}\"\"\"
"""


def _extract_json(text: str) -> Optional[dict]:
    """Safely extract JSON from Gemini's potentially markdown-wrapped response."""
    # Strip markdown code fences
    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Try to find first { ... }
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


async def gemini_classify(prompt_text: str, api_key: str) -> dict:
    """
    Send a prompt to Gemini for security classification.
    Uses shared cache + rate limiter when available to conserve free-tier quota.

    Returns:
        {
            "prediction": "credential_leak",
            "confidence": 0.95,
            "explanation": "Contains an API key pattern sk-..."
        }
        On failure, returns a fallback dict with "error" key.
    """
    if not _ensure_gemini_configured(api_key):
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "explanation": "Gemini API key not configured",
            "error": True,
        }

    # ── Check cache first (free!) ──
    if _HAS_CACHE:
        cached = gemini_cache.get(prompt_text, prefix="classify:")
        if cached is not None:
            cached["from_cache"] = True
            return cached

        # Check rate limiter
        if not gemini_rate_limiter.can_call():
            return {
                "prediction": "unknown",
                "confidence": 0.0,
                "explanation": f"Rate limited — {gemini_rate_limiter.calls_remaining} calls remaining. Try again shortly.",
                "rate_limited": True,
            }

    # Use configured model name with fallback chain
    try:
        from app.config import settings
        model_name = settings.GEMINI_MODEL
        fallback_models = settings.GEMINI_FALLBACK_MODELS
    except ImportError:
        model_name = "gemini-2.5-flash-lite"
        fallback_models = ["gemini-2.5-flash-lite", "gemini-2.5-flash", "gemma-3-4b-it"]

    # Build ordered model list: primary first, then fallbacks (deduped)
    models_to_try = [model_name] + [m for m in fallback_models if m != model_name]

    # Truncate long prompts to save tokens
    truncated = prompt_text[:500]
    classification_input = CLASSIFICATION_PROMPT.format(prompt=truncated)

    # Try each model until one works
    last_error = None
    for try_model in models_to_try:
        try:
            model = genai.GenerativeModel(
                try_model,
                generation_config=genai.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=1024,
                ),
            )

            # Run sync call in executor to avoid blocking the event loop
            import concurrent.futures
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                response = await loop.run_in_executor(
                    pool,
                    lambda m=model: m.generate_content(classification_input),
                )

            # If we get here, the call succeeded — parse the result
            result = _extract_json(response.text)
            if result and "prediction" in result:
                # Parse all_scores if Gemini returned them, otherwise synthesize
                all_scores = result.get("all_scores", {})
                if not all_scores or not isinstance(all_scores, dict):
                    pred = result["prediction"]
                    all_scores = {c: 0.01 for c in ["safe", "pii_leak", "credential_leak", "financial_data", "secret_code"]}
                    all_scores[pred] = float(result.get("confidence", 0.8))
                else:
                    all_scores = {k: float(v) for k, v in all_scores.items()}
                    total = sum(all_scores.values())
                    if total > 0 and abs(total - 1.0) > 0.05:
                        all_scores = {k: round(v / total, 4) for k, v in all_scores.items()}

                all_scores = {k: round(v, 4) for k, v in all_scores.items()}
                confidence = max(all_scores.values()) if all_scores else float(result.get("confidence", 0.0))

                success_dict = {
                    "prediction": result["prediction"],
                    "confidence": round(confidence, 4),
                    "all_scores": all_scores,
                    "explanation": result.get("explanation", ""),
                    "model_used": try_model,
                }
                if _HAS_CACHE:
                    gemini_cache.put(prompt_text, success_dict, prefix="classify:")
                return success_dict

            return {
                "prediction": "unknown",
                "confidence": 0.0,
                "explanation": f"Unparseable Gemini response: {response.text[:200]}",
                "parse_error": True,
                "model_used": try_model,
            }

        except Exception as model_err:
            error_msg = str(model_err)
            if "RESOURCE_EXHAUSTED" in error_msg or "quota" in error_msg.lower():
                last_error = model_err
                continue  # Try next model
            else:
                # Non-quota error — don't retry with other models
                last_error = model_err
                break

    # All models failed
    error_msg = str(last_error) if last_error else "Unknown error"
    if "RESOURCE_EXHAUSTED" in error_msg or "quota" in error_msg.lower():
        explanation = f"All Gemini models quota exhausted ({', '.join(models_to_try)}). Try again later."
        if _HAS_CACHE:
            gemini_rate_limiter.mark_quota_exhausted()
    elif "PERMISSION_DENIED" in error_msg or "API key" in error_msg:
        explanation = "Gemini API key is invalid or expired."
    else:
        explanation = f"Gemini API error: {error_msg[:200]}"

    return {
        "prediction": "unknown",
        "confidence": 0.0,
        "explanation": explanation,
        "error": True,
    }


# ──────────────────── Side-by-Side Comparison ────────────────────

DECISION_MAP = {
    "safe": "ALLOW",
    "pii_leak": "WARN",
    "credential_leak": "BLOCK",
    "financial_data": "BLOCK",
    "secret_code": "BLOCK",
}


def _derive_decision(local_pred: str, gemini_pred: str) -> str:
    """
    Derive a final decision from both predictions.
    Uses the stricter of the two (BLOCK > WARN > ALLOW).
    """
    severity = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
    local_decision = DECISION_MAP.get(local_pred, "WARN")
    gemini_decision = DECISION_MAP.get(gemini_pred, "WARN")

    if severity.get(gemini_decision, 0) >= severity.get(local_decision, 0):
        return gemini_decision
    return local_decision


async def compare_analysis(prompt_text: str, api_key: str) -> dict:
    """
    Run both the local ML model and Gemini on the same prompt,
    then return a side-by-side comparison.

    Args:
        prompt_text: The prompt to analyze.
        api_key: Gemini API key.

    Returns:
        {
            "prompt": "My API key is sk-123...",
            "local_model": {
                "prediction": "credential_leak",
                "confidence": 0.92,
                "all_scores": {...}
            },
            "gemini_analysis": {
                "prediction": "credential_leak",
                "confidence": 0.95,
                "explanation": "API key pattern detected"
            },
            "decision": "BLOCK",
            "agreement": True
        }
    """
    # Run local model (synchronous, fast)
    local_result = local_analyze(prompt_text)

    # Run Gemini (async)
    gemini_result = await gemini_classify(prompt_text, api_key)

    # Determine agreement
    agreement = local_result["prediction"] == gemini_result["prediction"]

    # Final decision: stricter of the two wins
    decision = _derive_decision(local_result["prediction"], gemini_result["prediction"])

    return {
        "prompt": prompt_text,
        "local_model": local_result,
        "gemini_analysis": gemini_result,
        "decision": decision,
        "agreement": agreement,
    }


# ──────────────────── Pretty Print ────────────────────

def print_comparison(result: dict):
    """Print a nicely formatted side-by-side comparison."""
    prompt = result["prompt"]
    local = result["local_model"]
    gemini = result["gemini_analysis"]

    print("\n" + "=" * 70)
    print(f"  Prompt: \"{prompt[:65]}{'...' if len(prompt) > 65 else ''}\"")
    print("=" * 70)

    print(f"\n  {'LOCAL MODEL':<35} {'GEMINI ANALYSIS'}")
    print(f"  {'-' * 33}   {'-' * 30}")
    print(f"  Prediction:  {local['prediction']:<20} Prediction:  {gemini['prediction']}")
    print(f"  Confidence:  {local['confidence']:<20.2%} Confidence:  {gemini['confidence']:.2%}")

    if gemini.get("explanation"):
        print(f"\n  Gemini Explanation: {gemini['explanation']}")

    print(f"\n  {'✅' if result['agreement'] else '⚠️'}  Agreement: {'Yes' if result['agreement'] else 'No'}")
    print(f"  🛡️  Final Decision: {result['decision']}")
    print("=" * 70)


# ──────────────────── CLI Entry Point ────────────────────

if __name__ == "__main__":
    import os
    import sys

    # Try loading API key from environment or .env
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
    api_key = os.getenv("GEMINI_API_KEY", "")

    if not api_key or api_key == "your_gemini_api_key_here":
        print("⚠️  GEMINI_API_KEY not set. Gemini results will show errors.")
        print("   Set it in backend/.env or as an environment variable.\n")

    test_prompts = [
        "My API key is sk-123456789abcdef",
        "My credit card is 4242 4242 4242 4242",
        "Explain recursion in Python",
        "My email is john@gmail.com and phone is 9876543210",
        "-----BEGIN RSA PRIVATE KEY-----",
    ]

    async def run_tests():
        for prompt in test_prompts:
            result = await compare_analysis(prompt, api_key)
            print_comparison(result)

    asyncio.run(run_tests())