from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests
import json
import os
from datetime import datetime, timedelta

app = FastAPI()

# Разрешаем запросы отовсюду (для теста)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")  # Берем из переменных окружения
CACHE_FILE = "cache.json"
CACHE_DURATION = timedelta(hours=1)  # Кеш на 1 час

def load_cache():
    """Загружает кеш из файла"""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_cache(cache):
    """Сохраняет кеш в файл"""
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)

def is_cache_valid(timestamp):
    """Проверяет актуальность кеша"""
    cached_time = datetime.fromisoformat(timestamp)
    return datetime.now() - cached_time < CACHE_DURATION

@app.get("/check-mint/{contract_address}")
async def check_mint(contract_address: str):
    """
    Checks if a contract has a mint function by fetching its ABI from Etherscan.
    """
    contract_address = contract_address.lower().strip()
    
    # Загружаем кеш
    cache = load_cache()
    
    # Проверяем кеш
    if contract_address in cache:
        cached_data = cache[contract_address]
        if is_cache_valid(cached_data['timestamp']):
            print(f"Returning cached result for {contract_address}")
            return cached_data['response']
    
    # Если нет в кеше - идем в Etherscan
    abi_url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    
    try:
        response = requests.get(abi_url)
        data = response.json()
        
        if data['status'] != '1' or not data['result']:
            result = {
                "address": contract_address,
                "has_mint": False,
                "error": "Contract ABI not found or not verified on Etherscan",
                "source": "Etherscan API (Live)"
            }
        else:
            contract_abi = json.loads(data['result'])
            
            # УЛУЧШЕННАЯ ПРОВЕРКА: ищем именно функцию MINT с параметрами
            has_mint = False
            for item in contract_abi:
                if (item.get('type') == 'function' and 
                    item.get('name') == 'mint' and 
                    'inputs' in item and 
                    len(item['inputs']) > 0):
                    # Проверяем, что это действительно функция создания токенов
                    # а не просто функция с похожим названием
                    has_mint = True
                    break
            
            result = {
                "address": contract_address,
                "has_mint": has_mint,
                "source": "Etherscan API (Live)"
            }
        
        # Сохраняем в кеш
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
    return {"message": "Orbis Scanner API is running", "version": "1.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
