from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import requests
import json
import os
from supabase import create_client, Client
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Orbis Scanner API", version="3.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Конфигурация
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
LEMON_SQUEEZY_WEBHOOK_SECRET = os.getenv("LEMON_SQUEEZY_WEBHOOK_SECRET")

# Инициализация Supabase
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Модели
class ContractAnalysisRequest(BaseModel):
    contract_address: str

class UserCreate(BaseModel):
    email: str

# Вспомогательные функции
async def get_user_by_api_key(api_key: str):
    try:
        response = supabase.table('users').select('*').eq('api_key', api_key).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return None

async def check_rate_limit(user_id: str):
    """Проверяет лимиты запросов для пользователя"""
    today = datetime.now(timezone.utc).date()
    today_start = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)
    
    # Получаем количество запросов за сегодня
    response = supabase.table('api_requests').select('id', count='exact').eq('user_id', user_id).gte('created_at', today_start.isoformat()).execute()
    
    request_count = response.count or 0
    
    # Получаем план подписки пользователя
    sub_response = supabase.table('subscriptions').select('plan_id').eq('user_id', user_id).eq('status', 'active').execute()
    
    plan = sub_response.data[0]['plan_id'] if sub_response.data else 'free'
    
    # Лимиты в зависимости от плана
    limits = {
        'free': 5,
        'premium': 1000
    }
    
    return request_count < limits.get(plan, 5)

async def log_api_request(user_id: str, ip_address: str, contract_address: str):
    """Логирует запрос в базу"""
    try:
        supabase.table('api_requests').insert({
            'user_id': user_id,
            'ip_address': ip_address,
            'contract_address': contract_address
        }).execute()
    except Exception as e:
        logger.error(f"Error logging request: {e}")

def analyze_contract_abi(contract_abi):
    """Анализирует ABI контракта"""
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
            
            # Mint проверка
            mint_keywords = ['mint', 'createtokens', 'generatetokens']
            if any(keyword in name for keyword in mint_keywords) and len(item.get('inputs', [])) > 0:
                results["has_mint"] = True
                results["mint_functions"].append(name)

            # Ownership проверка
            owner_keywords = ['transferownership', 'renounceownership', 'setowner', 'updateowner', 'addowner', 'removeowner']
            if any(keyword in name for keyword in owner_keywords):
                results["has_ownership"] = True
                results["owner_functions"].append(name)

            # Tax проверка
            tax_keywords = ['setfee', 'settax', 'updatefee', 'updatetax', 'setcommission']
            if any(keyword in name for keyword in tax_keywords):
                results["has_hidden_taxes"] = True
                results["tax_functions"].append(name)
    
    return results

# Роуты
@app.post("/analyze")
async def analyze_contract(
    request: ContractAnalysisRequest,
    x_api_key: str = Header(None),
    client_request: Request = None
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    user = await get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Проверка лимитов
    if not await check_rate_limit(user['id']):
        raise HTTPException(status_code=429, detail="Daily limit exceeded")
    
    # Логируем запрос
    client_ip = client_request.client.host if client_request else "unknown"
    await log_api_request(user['id'], client_ip, request.contract_address)
    
    # Анализ контракта (твоя существующая логика)
    contract_address = request.contract_address.lower().strip()
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
                    "tax_functions": [],
                    "mint_functions": []
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
        
        return result
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/create-user")
async def create_user(user_data: UserCreate):
    """Создает нового пользователя и возвращает API key"""
    try:
        # Проверяем, существует ли пользователь
        existing_user = supabase.table('users').select('*').eq('email', user_data.email).execute()
        
        if existing_user.data:
            user = existing_user.data[0]
        else:
            # Создаем нового пользователя
            new_user = supabase.table('users').insert({
                'email': user_data.email,
                'api_key': f"sk_{os.urandom(16).hex()}"
            }).execute()
            user = new_user.data[0]
            
            # Создаем бесплатную подписку
            supabase.table('subscriptions').insert({
                'user_id': user['id'],
                'status': 'active',
                'plan_id': 'free'
            }).execute()
        
        return {"api_key": user['api_key'], "email": user['email']}
        
    except Exception as e:
        logger.error(f"User creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")

@app.get("/user/stats")
async def get_user_stats(x_api_key: str = Header(None)):
    """Возвращает статистику пользователя"""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    user = await get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Получаем количество запросов за сегодня
    today = datetime.now(timezone.utc).date()
    today_start = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)
    
    response = supabase.table('api_requests').select('id', count='exact').eq('user_id', user['id']).gte('created_at', today_start.isoformat()).execute()
    requests_today = response.count or 0
    
    # Получаем информацию о подписке
    sub_response = supabase.table('subscriptions').select('*').eq('user_id', user['id']).execute()
    subscription = sub_response.data[0] if sub_response.data else None
    
    return {
        "email": user['email'],
        "requests_today": requests_today,
        "subscription": subscription,
        "limits": {
            "free": 5,
            "premium": 1000
        }
    }

@app.post("/lemon-webhook")
async def lemon_webhook(request: Request):
    """Обрабатывает вебхуки от Lemon Squeezy"""
    try:
        payload = await request.json()
        event_type = payload.get('meta', {}).get('event_name')
        
        if event_type == 'subscription_created':
            # Обработка новой подписки
            customer_email = payload['data']['attributes']['user_email']
            sub_id = payload['data']['id']
            
            # Находим или создаем пользователя
            user_response = supabase.table('users').select('*').eq('email', customer_email).execute()
            if user_response.data:
                user = user_response.data[0]
            else:
                # Создаем пользователя
                new_user = supabase.table('users').insert({
                    'email': customer_email,
                    'api_key': f"sk_{os.urandom(16).hex()}"
                }).execute()
                user = new_user.data[0]
            
            # Обновляем подписку
            supabase.table('subscriptions').upsert({
                'user_id': user['id'],
                'status': 'active',
                'plan_id': 'premium',
                'lemon_squeezy_id': sub_id,
                'current_period_end': datetime.now(timezone.utc) + timedelta(days=30)
            }).execute()
            
            logger.info(f"Premium subscription activated for {customer_email}")
        
        return JSONResponse(status_code=200, content={"status": "success"})
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

@app.get("/")
async def root():
    return {"message": "Orbis Scanner API is running", "version": "3.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
