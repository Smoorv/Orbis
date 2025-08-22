from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests
import json
import os
from datetime import datetime, timedelta
import re

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
CACHE_FILE = "cache.json"
CACHE_DURATION = timedelta(hours=1)

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)

def is_cache_valid(timestamp):
    cached_time = datetime.fromisoformat(timestamp)
    return datetime.now() - cached_time < CACHE_DURATION

def analyze_contract_abi(contract_abi):
    """Анализирует ABI контракта на наличие опасных функций"""
    results = {
        "has_mint": False,
        "has_ownership": False,
        "has_hidden_taxes": False,
        "owner_functions": [],
        "tax_functions": []
    }
    

    for item in contract_abi:
        if item.get('type') == 'function':
            name = item.get('name', '').lower()
            

            # Mint проверка - только функции которые могут mint'ить
            if name == 'mint' and len(item.get('inputs', [])) > 0:
                results["has_mint"] = True

            # Ownership проверка - только опасные функции
            owner_keywords = ['transferownership', 'renounceownership', 'setowner', 'updateowner']
            if any(keyword in name for keyword in owner_keywords):
                results["has_ownership"] = True
                results["owner_functions"].append(name)

            # Tax проверка - только setter функции
            tax_keywords = ['setfee', 'settax', 'updatefee', 'updatetax']
            if any(keyword in name for keyword in tax_keywords):
                results["has_hidden_taxes"] = True
                results["tax_functions"].append(name)
    
    return results

@app.get("/analyze/{contract_address}")
async def analyze_contract(contract_address: str):
    contract_address = contract_address.lower().strip()
    
    cache = load_cache()
    if contract_address in cache:
        cached_data = cache[contract_address]
        if is_cache_valid(cached_data['timestamp']):
            return cached_data['response']
    
    abi_url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    
    try:
        response = requests.get(abi_url)
        data = response.json()
        
        if data['status'] != '1' or not data['result']:
            result = {
                "address": contract_address,
                "analysis": {
                    "has_mint": False,
                    "has_ownership": False,
                    "has_hidden_taxes": False,
                    "owner_functions": [],
                    "tax_functions": []
                },
                "risk_score": 0,
                "verdict": "❓ Cannot analyze: Contract not verified",
                "source": "Etherscan API"
            }
        else:
            contract_abi = json.loads(data['result'])
            analysis = analyze_contract_abi(contract_abi)
            
            risk_score = 0
            if analysis["has_mint"]: risk_score += 30
            if analysis["has_ownership"]: risk_score += 40
            if analysis["has_hidden_taxes"]: risk_score += 30
            
            # Если ничего не найдено - низкий риск
            if risk_score == 0:
                verdict = "✅ LOW RISK: No critical issues found"
            elif risk_score >= 70:
                verdict = "🚨 CRITICAL RISK: High probability of scam"
            elif risk_score >= 30:
                verdict = "⚠️ MEDIUM RISK: Multiple red flags detected"
            else:
                verdict = "✅ LOW RISK: No critical issues found"
            
            result = {
                "address": contract_address,
                "analysis": analysis,
                "risk_score": risk_score,
                "verdict": verdict,
                "source": "Etherscan API (Live)"
            }
        
        
        cache[contract_address] = {
            'timestamp': datetime.now().isoformat(),
            'response': result
        }
        save_cache(cache)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/")
async def root():
    return {"message": "Orbis Scanner API is running", "version": "2.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
