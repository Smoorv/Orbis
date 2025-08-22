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
    """Точный анализ ABI контракта на наличие опасных функций"""
    results = {
        "has_dangerous_mint": False,
        "has_dangerous_ownership": False,
        "has_setter_taxes": False,
        "dangerous_functions": [],
        "risk_details": []
    }

    for item in contract_abi:
        if item.get('type') == 'function':
            name = item.get('name', '').lower()
            state_mutability = item.get('stateMutability', '')
            inputs = item.get('inputs', [])
            
            # Проверяем только функции, которые меняют состояние (не view/pure)
            if state_mutability not in ['view', 'pure']:
                
                # Опасные mint функции (которые могут создавать токены)
                mint_patterns = ['mint', 'createtoken', 'generatetoken']
                if any(pattern in name for pattern in mint_patterns) and len(inputs) > 0:
                    results["has_dangerous_mint"] = True
                    results["dangerous_functions"].append(name)
                    results["risk_details"].append(f"Dangerous mint function: {name}")
                
                # Опасные ownership функции (которые меняют владельца)
                dangerous_ownership = [
                    'transferownership', 'renounceownership', 'setowner', 
                    'updateowner', 'changeowner', 'addowner', 'removeowner',
                    'setadmin', 'changeadmin', 'transferadmin'
                ]
                if name in dangerous_ownership:
                    results["has_dangerous_ownership"] = True
                    results["dangerous_functions"].append(name)
                    results["risk_details"].append(f"Dangerous ownership function: {name}")
                
                # Функции установки налогов/комиссий (setter функции)
                tax_setters = [
                    'setfee', 'settax', 'updatefee', 'updatetax', 'changefee', 
                    'changetax', 'setcommission', 'updatecommission', 'changecommission',
                    'setrat', 'updaterat', 'changerat'  # ratio
                ]
                if name in tax_setters:
                    results["has_setter_taxes"] = True
                    results["dangerous_functions"].append(name)
                    results["risk_details"].append(f"Tax setter function: {name}")
            
            # Дополнительно проверяем view функции на наличие признаков ownership
            else:
                ownership_view_patterns = ['owner', 'admin', 'controller']
                if any(pattern in name for pattern in ownership_view_patterns):
                    results["risk_details"].append(f"Ownership view function detected: {name}")

    return results

def calculate_risk_score(analysis):
    """Точная оценка рисков на основе обнаруженных опасных функций"""
    risk_score = 0
    
    # Веса рисков
    if analysis["has_dangerous_mint"]:
        risk_score += 35
    if analysis["has_dangerous_ownership"]:
        risk_score += 40
    if analysis["has_setter_taxes"]:
        risk_score += 25
    
    # Дополнительные баллы за множественные опасные функции
    dangerous_count = len(analysis["dangerous_functions"])
    if dangerous_count > 1:
        risk_score += min((dangerous_count - 1) * 10, 20)
    
    return min(risk_score, 100)  # Ограничиваем максимум 100

def generate_verdict(risk_score, analysis):
    """Генерация точного вердикта на основе оценки риска"""
    if risk_score >= 80:
        verdict = "🚨 CRITICAL RISK: Multiple dangerous functions detected"
    elif risk_score >= 60:
        verdict = "⚠️ HIGH RISK: Significant control risks present"
    elif risk_score >= 40:
        verdict = "🟡 MEDIUM RISK: Some concerning features found"
    elif risk_score >= 20:
        verdict = "🔵 MODERATE RISK: Minor issues detected"
    else:
        verdict = "✅ LOW RISK: No critical dangerous functions found"
    
    return verdict

@app.get("/analyze/{contract_address}")
async def analyze_contract(contract_address: str):
    contract_address = contract_address.lower().strip()
    
    # Проверяем валидность адреса Ethereum
    if not re.match(r'^0x[a-f0-9]{40}$', contract_address):
        raise HTTPException(status_code=400, detail="Invalid Ethereum address format")
    
    cache = load_cache()
    if contract_address in cache:
        cached_data = cache[contract_address]
        if is_cache_valid(cached_data['timestamp']):
            return cached_data['response']
    
    abi_url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    
    try:
        response = requests.get(abi_url, timeout=10)
        data = response.json()
        
        if data['status'] != '1' or not data['result'] or data['result'] == 'Contract source code not verified':
            result = {
                "address": contract_address,
                "analysis": {
                    "has_dangerous_mint": False,
                    "has_dangerous_ownership": False,
                    "has_setter_taxes": False,
                    "dangerous_functions": [],
                    "risk_details": ["Contract not verified or ABI not available"]
                },
                "risk_score": 10,
                "verdict": "❓ Cannot analyze: Contract not verified",
                "source": "Etherscan API",
                "timestamp": datetime.now().isoformat()
            }
        else:
            contract_abi = json.loads(data['result'])
            analysis = analyze_contract_abi(contract_abi)
            risk_score = calculate_risk_score(analysis)
            verdict = generate_verdict(risk_score, analysis)
            
            result = {
                "address": contract_address,
                "analysis": analysis,
                "risk_score": risk_score,
                "verdict": verdict,
                "source": "Etherscan API (Live)",
                "timestamp": datetime.now().isoformat()
            }
        
        # Сохраняем в кэш
        cache[contract_address] = {
            'timestamp': datetime.now().isoformat(),
            'response': result
        }
        save_cache(cache)
        
        return result
        
    except requests.Timeout:
        raise HTTPException(status_code=504, detail="Etherscan API timeout")
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Etherscan API error: {str(e)}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid JSON response from Etherscan")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/")
async def root():
    return {
        "message": "Orbis Scanner API is running", 
        "version": "2.0",
        "endpoints": {
            "analyze": "/analyze/{contract_address}",
            "health": "/health"
        }
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
