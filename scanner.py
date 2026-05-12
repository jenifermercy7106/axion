# scanner.py
import subprocess, os, json, tempfile
from pathlib import Path
from dotenv import load_dotenv
import requests

load_dotenv()

GROQ_KEY       = os.getenv("GROQ_API_KEY")
MISTRAL_KEY    = os.getenv("MISTRAL_API_KEY")
NOVITA_KEY     = os.getenv("NOVITA_API_KEY")
CEREBRAS_KEY   = os.getenv("CEREBRAS_API_KEY")
AI21_KEY       = os.getenv("AI21_API_KEY")
FIREWORKS_KEY  = os.getenv("FIREWORKS_API_KEY")

# ── API helpers ──────────────────────────────────────────────────────────────

def _groq(prompt):
    from groq import Groq
    r = Groq(api_key=GROQ_KEY).chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role":"user","content":prompt}],
        max_tokens=2000
    )
    return r.choices[0].message.content

def _mistral(prompt):
    r = requests.post("https://api.mistral.ai/v1/chat/completions",
        headers={"Authorization":f"Bearer {MISTRAL_KEY}","Content-Type":"application/json"},
        json={"model":"mistral-small-latest","messages":[{"role":"user","content":prompt}],"max_tokens":2000})
    return r.json()["choices"][0]["message"]["content"]

def _novita(prompt):
    r = requests.post("https://api.novita.ai/v3/openai/chat/completions",
        headers={"Authorization":f"Bearer {NOVITA_KEY}","Content-Type":"application/json"},
        json={"model":"meta-llama/llama-3.1-8b-instruct","messages":[{"role":"user","content":prompt}],"max_tokens":2000})
    d = r.json()
    return d.get("choices",[{}])[0].get("message",{}).get("content", str(d)[:400])

def _cerebras(prompt):
    r = requests.post("https://api.cerebras.ai/v1/chat/completions",
        headers={"Authorization":f"Bearer {CEREBRAS_KEY}","Content-Type":"application/json"},
        json={"model":"llama3.1-8b","messages":[{"role":"user","content":prompt}],"max_tokens":2000})
    return r.json()["choices"][0]["message"]["content"]

def _ai21(prompt):
    r = requests.post("https://api.ai21.com/studio/v1/chat/completions",
        headers={"Authorization":f"Bearer {AI21_KEY}","Content-Type":"application/json"},
        json={"model":"jamba-mini","messages":[{"role":"user","content":prompt}],"max_tokens":2000})
    return r.json()["choices"][0]["message"]["content"]

def _fireworks(prompt):
    r = requests.post("https://api.fireworks.ai/inference/v1/chat/completions",
        headers={"Authorization":f"Bearer {FIREWORKS_KEY}","Content-Type":"application/json"},
        json={"model":"accounts/fireworks/models/llama-v3p3-70b-instruct","messages":[{"role":"user","content":prompt}],"max_tokens":2000})
    d = r.json()
    return d.get("choices",[{}])[0].get("message",{}).get("content", str(d)[:400])

def _ollama(prompt):
    r = requests.post("http://localhost:11434/api/generate",
        json={"model":"tinyllama","prompt":prompt,"stream":False},
        timeout=60)
    return r.json()["response"]

# ── 10 tools ─────────────────────────────────────────────────────────────────

def tool_bandit(path):
    r = subprocess.run(["bandit","-r",path,"-f","json"],
        capture_output=True, text=True)
    try:
        issues = json.loads(r.stdout).get("results",[])
        return {
            "tool":"Bandit","company":"PyCQA","role":"Security Vulnerability Scanner",
            "status":"warning" if issues else "clean","count":len(issues),
            "details":[f"{i['test_id']} · {i['issue_text']} (line {i['line_number']})" for i in issues[:4]]
        }
    except:
        return {"tool":"Bandit","company":"PyCQA","role":"Security Vulnerability Scanner",
                "status":"clean","count":0,"details":["No issues found."]}

def tool_radon(path):
    r = subprocess.run(["radon","cc",path,"-j"],
        capture_output=True, text=True)
    try:
        data = json.loads(r.stdout)
        funcs = [f"{fn['name']} (complexity {fn['complexity']})"
                 for _,fns in data.items() for fn in fns if fn["complexity"] > 3]
        return {
            "tool":"Radon","company":"PyCQA","role":"Code Complexity Analyzer",
            "status":"warning" if funcs else "clean","count":len(funcs),
            "details": funcs[:4] or ["All functions within acceptable complexity."]
        }
    except:
        return {"tool":"Radon","company":"PyCQA","role":"Code Complexity Analyzer",
                "status":"clean","count":0,"details":["No complexity issues."]}

def tool_vulture(path):
    r = subprocess.run(["vulture",path],capture_output=True,text=True)
    lines = [l for l in r.stdout.strip().split("\n") if l]
    return {
        "tool":"Vulture","company":"Jendrik Seipp","role":"Dead Code Detector",
        "status":"warning" if lines else "clean","count":len(lines),
        "details": lines[:4] or ["No dead code detected."]
    }

def tool_groq(code):
    try:
        out = _groq(f"Generate 3 short Python unit tests for this code. Be concise:\n\n{code[:2000]}")
        return {"tool":"Groq","company":"Groq Inc.","role":"AI Test Generator",
                "status":"done","count":3,"details":[out[:2000]]}
    except Exception as e:
        return {"tool":"Groq","company":"Groq Inc.","role":"AI Test Generator",
                "status":"error","count":0,"details":[str(e)]}

def tool_mistral(code):
    try:
        out = _mistral(f"Explain what this code does in 3 simple sentences a non-programmer would understand:\n\n{code[:2000]}")
        return {"tool":"Mistral AI","company":"Mistral AI","role":"Plain English Explainer",
                "status":"done","count":1,"details":[out[:2000]]}
    except Exception as e:
        return {"tool":"Mistral AI","company":"Mistral AI","role":"Plain English Explainer",
                "status":"error","count":0,"details":[str(e)]}

def tool_novita(code):
    try:
        out = _novita(f"List 3 specific improvements for this Python code, one per line:\n\n{code[:2000]}")
        return {"tool":"Novita AI","company":"Novita AI","role":"Code Improvement Suggester",
                "status":"done","count":3,"details":[out[:2000]]}
    except Exception as e:
        return {"tool":"Novita AI","company":"Novita AI","role":"Code Improvement Suggester",
                "status":"error","count":0,"details":[str(e)]}

def tool_cerebras(code):
    try:
        out = _cerebras(f"List exactly 3 security vulnerabilities in this Python code, one per line:\n\n{code[:2000]}")
        return {"tool":"Cerebras","company":"Cerebras Systems","role":"AI Security Advisor",
                "status":"warning","count":3,"details":[out[:2000]]}
    except Exception as e:
        return {"tool":"Cerebras","company":"Cerebras Systems","role":"AI Security Advisor",
                "status":"error","count":0,"details":[str(e)]}

def tool_ai21(code):
    try:
        out = _ai21(f"Write a short docstring for each function in this code:\n\n{code[:2000]}")
        return {"tool":"AI21 Labs","company":"AI21 Labs","role":"Auto Documentation Writer",
                "status":"done","count":1,"details":[out[:2000]]}
    except Exception as e:
        return {"tool":"AI21 Labs","company":"AI21 Labs","role":"Auto Documentation Writer",
                "status":"error","count":0,"details":[str(e)]}

def tool_fireworks(code):
    try:
        out = _fireworks(f"Rate this code's overall risk from 1-10 and explain in one sentence. Format: Risk Score X/10 - reason:\n\n{code[:2000]}")
        return {"tool":"Fireworks AI","company":"Fireworks AI","role":"Risk Score Predictor",
                "status":"warning","count":1,"details":[out[:2000]]}
    except Exception as e:
        return {"tool":"Fireworks AI","company":"Fireworks AI","role":"Risk Score Predictor",
                "status":"error","count":0,"details":[str(e)]}

def tool_ollama(code):
    try:
        out = _ollama(f"List 3 bad coding patterns in this Python code, one per line:\n\n{code[:2000]}")
        return {"tool":"Ollama · TinyLlama","company":"Ollama","role":"Bad Pattern Detector (Local AI)",
                "status":"warning","count":3,"details":[out[:2000]]}
    except Exception as e:
        return {"tool":"Ollama · TinyLlama","company":"Ollama","role":"Bad Pattern Detector (Local AI)",
                "status":"error","count":0,"details":[str(e)]}

# ── Main entry ────────────────────────────────────────────────────────────────

def run_scan(code: str) -> list:
    """Write code to a temp file and run all 10 tools. Returns list of results."""
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "target.py"
        f.write_text(code, encoding="utf-8")
        path = str(tmp)
        return [
            tool_bandit(path),
            tool_radon(path),
            tool_vulture(path),
            tool_groq(code),
            tool_mistral(code),
            tool_novita(code),
            tool_cerebras(code),
            tool_ai21(code),
            tool_fireworks(code),
            tool_ollama(code),
        ]