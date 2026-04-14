from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import json
import joblib
import pandas as pd
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# загрузка ML модели
model = joblib.load('scam_model.pkl')

feature_cols = ['has_mint', 'has_owner', 'has_tax', 'has_pause',
                'has_blacklist', 'has_upgrade', 'has_selfdestruct',
                'num_functions', 'num_events', 'has_fallback', 'has_receive']

API_KEY = "etherscan ключ"  

class AnalyzeRequest(BaseModel):
    contract_address: str

def analyze_contract_abi(contract_abi):
    results = {
        "has_mint": False,
        "has_ownership": False,
        "has_hidden_taxes": False,
        "owner_functions": [],
        "tax_functions": [],
        "mint_functions": []
    }
    
    for item in contract_abi:
        if item.get('type') == 'function':
            name = item.get('name', '').lower()
            
            mint_keywords = ['mint', 'createtokens', 'generatetokens']
            if any(keyword in name for keyword in mint_keywords) and len(item.get('inputs', [])) > 0:
                results["has_mint"] = True
                results["mint_functions"].append(name)
            
            owner_keywords = ['transferownership', 'renounceownership', 'setowner', 'updateowner', 'addowner', 'removeowner']
            if any(keyword in name for keyword in owner_keywords):
                results["has_ownership"] = True
                results["owner_functions"].append(name)
            
            tax_keywords = ['setfee', 'settax', 'updatefee', 'updatetax', 'setcommission']
            if any(keyword in name for keyword in tax_keywords):
                results["has_hidden_taxes"] = True
                results["tax_functions"].append(name)
    
    return results

# чтение abi контракта и извлечение признаков для ML модели и пользователя
def extract_ml_features(abi):
    features = {col: 0 for col in feature_cols}
    
    for item in abi:
        if item.get('type') == 'function':
            features['num_functions'] += 1
            name = item.get('name', '').lower()
            
            if 'mint' in name:
                features['has_mint'] = 1
            if 'owner' in name or 'ownership' in name:
                features['has_owner'] = 1
            if 'fee' in name or 'tax' in name:
                features['has_tax'] = 1
            if 'pause' in name:
                features['has_pause'] = 1
            if 'blacklist' in name:
                features['has_blacklist'] = 1
            if 'upgrade' in name:
                features['has_upgrade'] = 1
            if 'selfdestruct' in name or 'suicide' in name:
                features['has_selfdestruct'] = 1
        
        elif item.get('type') == 'event':
            features['num_events'] += 1
        elif item.get('type') == 'fallback':
            features['has_fallback'] = 1
        elif item.get('type') == 'receive':
            features['has_receive'] = 1
    
    return features

@app.post("/analyze")
async def analyze_contract(request: AnalyzeRequest):
    address = request.contract_address.lower().strip()
    
    url = f"https://api.etherscan.io/v2/api?module=contract&action=getabi&address={address}&apikey={API_KEY}&chainid=1"
    
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if data.get('status') != '1' or not data.get('result'):
            return {
                "address": address,
                "analysis": {
                    "has_mint": False,
                    "has_ownership": False,
                    "has_hidden_taxes": False,
                    "owner_functions": [],
                    "tax_functions": [],
                    "mint_functions": []
                },
                "risk_score": 0,
                "verdict": "Cannot analyze: Contract not verified",
                "source": "Etherscan API"
            }
        
        abi = json.loads(data['result'])
        
        # анализ по хард код првилам, чтобы пользваотель видел откуда берется оценка
        analysis = analyze_contract_abi(abi)
        
        # ML предсказание
        ml_features = extract_ml_features(abi)
        features_df = pd.DataFrame([ml_features])[feature_cols]
        proba = model.predict_proba(features_df)[0]
        ml_score = int(proba[1] * 100)
        
        # итоговая оценка риска берется из модели
        risk_score = ml_score
        
        if risk_score == 0:
            verdict = "LOW RISK: No critical issues found"
        elif risk_score >= 70:
            verdict = "CRITICAL RISK: High probability of scam"
        elif risk_score >= 30:
            verdict = "MEDIUM RISK: Multiple red flags detected"
        else:
            verdict = "LOW RISK: No critical issues found"
        
        return {
            "address": address,
            "analysis": analysis,
            "risk_score": risk_score,
            "verdict": verdict,
            "source": "ML Model (RandomForest, 92% accuracy)",
            "ml_confidence": round(proba[1], 3)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)