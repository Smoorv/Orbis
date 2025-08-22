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
    """Сверхточный анализ ABI контракта на наличие опасных функций"""
    results = {
        "has_dangerous_mint": False,
        "has_dangerous_ownership": False,
        "has_setter_taxes": False,
        "dangerous_functions": [],
        "risk_details": [],
        "detected_functions": []
    }

    for item in contract_abi:
        if item.get('type') == 'function':
            name = item.get('name', '').lower()
            state_mutability = item.get('stateMutability', '')
            inputs = item.get('inputs', [])
            
            # Записываем все обнаруженные функции для отладки
            results["detected_functions"].append({
                "name": name,
                "state_mutability": state_mutability,
                "inputs_count": len(inputs)
            })
            
            # Проверяем только функции, которые меняют состояние (не view/pure)
            if state_mutability not in ['view', 'pure']:
                
                # ТОЛЬКО действительно опасные mint функции
                dangerous_mint_patterns = [
                    'mint', 'createtoken', 'generatetoken', 'print'
                ]
                # Проверяем точное совпадение или начало названия
                is_dangerous_mint = any(
                    name == pattern or 
                    name.startswith(pattern) and not name.endswith(('role', 'ed', 'er'))
                    for pattern in dangerous_mint_patterns
                )
                
                if is_dangerous_mint and len(inputs) >= 1:
                    results["has_dangerous_mint"] = True
                    results["dangerous_functions"].append(name)
                    results["risk_details"].append(f"Dangerous mint function: {name}")
                
                # ТОЛЬКО конкретные опасные ownership функции
                dangerous_ownership_functions = {
                    'transferownership', 'renounceownership', 'setowner', 
                    'updateowner', 'changeowner', 'addowner', 'removeowner',
                    'setadmin', 'changeadmin', 'transferadmin', 'claimownership'
                }
                
                if name in dangerous_ownership_functions:
                    results["has_dangerous_ownership"] = True
                    results["dangerous_functions"].append(name)
                    results["risk_details"].append(f"Dangerous ownership function: {name}")
                
                # ТОЛЬКО конкретные setter функции для налогов
                tax_setter_functions = {
                    'setfee', 'settax', 'updatefee', 'updatetax', 'changefee', 
                    'changetax', 'setcommission', 'updatecommission', 'changecommission',
                    'setratio', 'updateratio', 'changeratio'
                }
                
                if name in tax_setter_functions:
                    results["has_setter_taxes"] = True
                    results["dangerous_functions"].append(name)
                    results["risk_details"].append(f"Tax setter function: {name}")

    return results

def calculate_risk_score(analysis):
    """Точная оценка рисков ТОЛЬКО при наличии реальных опасных функций"""
    risk_score = 0
    
    # Веса рисков - ТОЛЬКО если найдены реальные опасные функции
    if analysis["has_dangerous_mint"]:
        risk_score += 35
    if analysis["has_dangerous_ownership"]:
        risk_score += 40
    if analysis["has_setter_taxes"]:
        risk_score += 25
    
    # Если нет опасных функций, но есть другие - минимальный риск
    if risk_score == 0 and analysis["detected_functions"]:
        risk_score = 5  # Минимальный риск для верифицированных контрактов
    
    return min(risk_score, 100)

def generate_verdict(risk_score, analysis):
    """Генерация точного вердикта"""
    if risk_score >= 70:
        return "🚨 CRITICAL RISK: Multiple dangerous functions detected"
    elif risk_score >= 50:
        return "⚠️ HIGH RISK: Significant control risks present"
    elif risk_score >= 30:
        return "🟡 MEDIUM RISK: Some concerning features found"
    elif risk_score >= 10:
        return "🔵 LOW RISK: Minor potential issues"
    elif risk_score == 5:
        return "✅ SECURE: No dangerous functions detected"
    else:
        return "✅ VERIFIED: Contract is safe"

def generate_security_status(analysis):
    """Генерация статусов безопасности для каждой категории"""
    statuses = []
    
    if not analysis["has_dangerous_mint"]:
        statuses.append("✅ Mint Function Detection: Secure - No dangerous mint function detected")
    else:
        statuses.append("❌ Mint Function Detection: Dangerous mint function found")
    
    if not analysis["has_dangerous_ownership"]:
        statuses.append("✅ Ownership Control: Secure - No dangerous owner control detected")
    else:
        statuses.append("❌ Ownership Control: Dangerous owner control functions found")
    
    if not analysis["has_setter_taxes"]:
        statuses.append("✅ Hidden Taxes: Secure - No tax setter functions detected")
    else:
        statuses.append("❌ Hidden Taxes: Tax setter functions found")
    
    return statuses

@app.get("/analyze/{contract_address}")
async def analyze_contract(contract_address: str):
    contract_address = contract_address.lower().strip()
    
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
            # Для неверифицированных контрактов - высокий риск
            result = {
                "address": contract_address,
                "analysis": {
                    "has_dangerous_mint": False,
                    "has_dangerous_ownership": False,
                    "has_setter_taxes": False,
                    "dangerous_functions": [],
                    "risk_details": ["Contract not verified - high risk"],
                    "detected_functions": []
                },
                "risk_score": 85,
                "verdict": "🚨 HIGH RISK: Contract not verified",
                "security_status": [
                    "❌ Contract Verification: Not verified - High risk",
                    "⚠️ Analysis limited: Cannot analyze unverified contract"
                ],
                "source": "Etherscan API",
                "timestamp": datetime.now().isoformat()
            }
        else:
            contract_abi = json.loads(data['result'])
            analysis = analyze_contract_abi(contract_abi)
            risk_score = calculate_risk_score(analysis)
            verdict = generate_verdict(risk_score, analysis)
            security_status = generate_security_status(analysis)
            
            result = {
                "address": contract_address,
                "analysis": analysis,
                "risk_score": risk_score,
                "verdict": verdict,
                "security_status": security_status,
                "source": "Etherscan API (Live)",
                "timestamp": datetime.now().isoformat()
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
    return {"message": "Orbis Scanner API is running", "version": "2.1"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
