from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import requests
import json
import os
import hashlib
import hmac
from supabase import create_client, Client
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Orbis Scanner API", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
LEMON_SQUEEZY_WEBHOOK_SECRET = os.getenv("LEMON_SQUEEZY_WEBHOOK_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

class ContractAnalysisRequest(BaseModel):
    contract_address: str

class UserCreate(BaseModel):
    email: str

async def get_user_by_api_key(api_key: str):
    try:
        response = supabase.table('users').select('*').eq('api_key', api_key).execute()
        # ИСПРАВЛЕНО: проверка на пустой массив
        return response.data[0] if response.data and len(response.data) > 0 else None
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return None

async def check_rate_limit(user_id: str):
    today = datetime.now(timezone.utc).date()
    today_start = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)
    
    response = supabase.table('api_requests').select('id', count='exact').eq('user_id', user_id).gte('created_at', today_start.isoformat()).execute()
    request_count = response.count or 0
    
    sub_response = supabase.table('subscriptions').select('plan_id').eq('user_id', user_id).eq('status', 'active').execute()
    # ИСПРАВЛЕНО: проверка на пустой массив
    plan = sub_response.data[0]['plan_id'] if sub_response.data and len(sub_response.data) > 0 else 'free'
    
    limits = {'free': 5, 'premium': 1000}
    return request_count < limits.get(plan, 5)

async def log_api_request(user_id: str, ip_address: str, contract_address: str):
    try:
        supabase.table('api_requests').insert({
            'user_id': user_id,
            'ip_address': ip_address,
            'contract_address': contract_address
        }).execute()
    except Exception as e:
        logger.error(f"Error logging request: {e}")

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

def verify_lemonsqueezy_webhook(payload: bytes, signature: str) -> bool:
    if not LEMON_SQUEEZY_WEBHOOK_SECRET:
        logger.warning("Lemon Squeezy webhook secret not set")
        return True
        
    digest = hmac.new(
        LEMON_SQUEEZY_WEBHOOK_SECRET.encode(),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(digest, signature)

def is_valid_ethereum_address(address: str) -> bool:
    """Basic Ethereum address validation"""
    if not address.startswith('0x'):
        return False
    if len(address) != 42:
        return False
    try:
        int(address, 16)
        return True
    except ValueError:
        return False

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
    
    if not await check_rate_limit(user['id']):
        raise HTTPException(status_code=429, detail="Daily limit exceeded. Upgrade to Premium for unlimited access.")
    
    # Валидация Ethereum адреса
    if not is_valid_ethereum_address(request.contract_address):
        raise HTTPException(status_code=400, detail="Invalid Ethereum address format")
    
    client_ip = client_request.client.host if client_request else "unknown"
    await log_api_request(user['id'], client_ip, request.contract_address)
    
    contract_address = request.contract_address.lower().strip()
    abi_url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    
    try:
        response = requests.get(abi_url, timeout=10)
        data = response.json()
        
        if data.get('status') != '1' or not data.get('result'):
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
                "verdict": "❓ Cannot analyze: Contract not verified or ABI not available",
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
        
    except requests.exceptions.Timeout:
        logger.error(f"Etherscan API timeout for address: {contract_address}")
        raise HTTPException(status_code=408, detail="Etherscan API timeout. Please try again.")
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON response from Etherscan for address: {contract_address}")
        raise HTTPException(status_code=502, detail="Invalid response from Etherscan API.")
    except Exception as e:
        logger.error(f"Analysis error for {contract_address}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/create-user")
async def create_user(user_data: UserCreate):
    try:
        # Валидация email
        if not user_data.email or '@' not in user_data.email:
            raise HTTPException(status_code=400, detail="Valid email required")
        
        existing_user = supabase.table('users').select('*').eq('email', user_data.email).execute()
        
        # ИСПРАВЛЕНО: проверка на пустой массив
        if existing_user.data and len(existing_user.data) > 0:
            user = existing_user.data[0]
        else:
            new_user = supabase.table('users').insert({
                'email': user_data.email,
                'api_key': f"sk_{os.urandom(16).hex()}"
            }).execute()
            
            if not new_user.data or len(new_user.data) == 0:
                raise HTTPException(status_code=500, detail="Failed to create user")
                
            user = new_user.data[0]
            
            # Создаем бесплатную подписку по умолчанию
            supabase.table('subscriptions').insert({
                'user_id': user['id'],
                'status': 'active',
                'plan_id': 'free'
            }).execute()
        
        return {"api_key": user['api_key'], "email": user['email']}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")

@app.get("/user/stats")
async def get_user_stats(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    user = await get_user_by_api_key(x_api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    today = datetime.now(timezone.utc).date()
    today_start = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)
    
    response = supabase.table('api_requests').select('id', count='exact').eq('user_id', user['id']).gte('created_at', today_start.isoformat()).execute()
    requests_today = response.count or 0
    
    sub_response = supabase.table('subscriptions').select('*').eq('user_id', user['id']).execute()
    subscription = sub_response.data[0] if sub_response.data and len(sub_response.data) > 0 else None
    
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
    try:
        body = await request.body()
        signature = request.headers.get('x-signature')
        
        if not verify_lemonsqueezy_webhook(body, signature):
            logger.warning("Invalid webhook signature")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
        payload = json.loads(body)
        event_name = payload.get('meta', {}).get('event_name')
        data = payload.get('data', {})
        
        logger.info(f"Received webhook: {event_name}")
        
        if event_name in ['subscription_created', 'subscription_updated', 'subscription_payment_success']:
            customer_email = data['attributes']['user_email']
            sub_id = data['id']
            status = data['attributes']['status']
            
            user_response = supabase.table('users').select('*').eq('email', customer_email).execute()
            # ИСПРАВЛЕНО: проверка на пустой массив
            if user_response.data and len(user_response.data) > 0:
                user = user_response.data[0]
            else:
                # Создаем пользователя если не существует
                new_user = supabase.table('users').insert({
                    'email': customer_email,
                    'api_key': f"sk_{os.urandom(16).hex()}"
                }).execute()
                
                if not new_user.data or len(new_user.data) == 0:
                    logger.error(f"Failed to create user for webhook: {customer_email}")
                    raise HTTPException(status_code=500, detail="Failed to create user")
                    
                user = new_user.data[0]
            
            plan_id = 'premium' if status in ['active', 'trialing'] else 'free'
            
            # Обновляем или создаем подписку
            supabase.table('subscriptions').upsert({
                'user_id': user['id'],
                'status': status,
                'plan_id': plan_id,
                'lemon_squeezy_id': sub_id,
                'current_period_end': datetime.now(timezone.utc) + timedelta(days=30)
            }).execute()
            
            logger.info(f"Subscription updated for {customer_email}: {status} -> {plan_id}")
        
        return JSONResponse(status_code=200, content={"status": "success"})
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy", 
        "version": "4.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/")
async def root():
    return {"message": "Orbis Scanner API is running", "version": "4.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
