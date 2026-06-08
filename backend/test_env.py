"""
Quick connectivity check for the Gemini API key in your .env.
Uses the standard library only (same approach as app/routers/ai.py),
so it needs no extra dependencies.

Run:  python test_env.py
"""
import json
import os
import urllib.request
import urllib.error

from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY", "")
MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


def main():
    if not API_KEY:
        print("❌ GEMINI_API_KEY is not set in .env")
        return

    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={API_KEY}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models = [m.get("name", "") for m in data.get("models", [])]
        print(f"✅ Gemini API reachable. Configured model: {MODEL}")
        print(f"   {len(models)} models available:")
        for name in models:
            print(f"   - {name}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        print(f"❌ Gemini API error {e.code}: {body[:300]}")
    except Exception as e:
        print(f"❌ Could not reach Gemini API: {e}")


if __name__ == "__main__":
    main()
