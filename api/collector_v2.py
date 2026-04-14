import requests
import json
import csv
import time
import os
from datetime import datetime

class FeatureExtractor:
    def __init__(self, api_key):
        self.api_key = api_key
    
    def get_contract_features(self, address):
        url = f"https://api.etherscan.io/v2/api?module=contract&action=getabi&address={address}&apikey={self.api_key}&chainid=1"
        
        try:
            r = requests.get(url, timeout=10)
            data = r.json()
            
            if data.get('status') != '1':
                print(f"   Ошибка API для {address[:10]}: {data.get('message')}")
                return None
            
            abi = json.loads(data['result'])
            
            features = self._extract_abi_features(abi)
            features['address'] = address
            
            return features
            
        except Exception as e:
            print(f"   Ошибка: {e}")
            return None
    
    def _extract_abi_features(self, abi):
        features = {
            'has_mint': 0,
            'has_owner': 0,
            'has_tax': 0,
            'has_pause': 0,
            'has_blacklist': 0,
            'has_upgrade': 0,
            'has_selfdestruct': 0,
            'num_functions': 0,
            'num_events': 0,
            'has_fallback': 0,
            'has_receive': 0
        }
        
        for item in abi:
            item_type = item.get('type')
            
            if item_type == 'function':
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
            
            elif item_type == 'event':
                features['num_events'] += 1
            elif item_type == 'fallback':
                features['has_fallback'] = 1
            elif item_type == 'receive':
                features['has_receive'] = 1
        
        return features

def collect_dataset():    
    base_dir = r"C:\Users\home_\Projects\Orbis"
    addresses_path = os.path.join(base_dir, "addresses.txt")
    dataset_path = os.path.join(base_dir, "dataset.csv")
    
    API_KEY = "3ZGETUBI216TVUVGDYT7QVX58CZNZT6VKM"
    
    if not os.path.exists(addresses_path):
        print(f"Файл {addresses_path} не найден")
        return
    
    addresses = []
    with open(addresses_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and ',' in line and not line.startswith('#'):
                addr, label = line.split(',')
                addresses.append((addr.strip(), int(label.strip())))
    
    print(f"Найдено {len(addresses)} адресов в addresses.txt")
    
    existing = {}
    if os.path.exists(dataset_path):
        with open(dataset_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing[row['address']] = row
        print(f"Загружено {len(existing)} существующих записей")
    
    extractor = FeatureExtractor(API_KEY)
    
    new_data = []
    for i, (addr, label) in enumerate(addresses, 1):
        if addr in existing:
            print(f"[{i}/{len(addresses)}] ⏭️ {addr[:10]}... уже есть")
            continue
        
        print(f"[{i}/{len(addresses)}] {addr[:10]}...")
        features = extractor.get_contract_features(addr)
        
        if features:
            features['is_scam'] = label
            new_data.append(features)
            print(f"   {features['num_functions']} функций, {features['num_events']} событий")
        else:
            print(f"  Не удалось")
        
        time.sleep(0.3)
    
    if new_data or existing:
        all_records = list(existing.values())
        
        for record in new_data:
            all_records.append(record)
        
        if all_records:
            with open(dataset_path, 'w', newline='') as f:
                fieldnames = ['address', 'has_mint', 'has_owner', 'has_tax', 
                             'has_pause', 'has_blacklist', 'has_upgrade', 
                             'has_selfdestruct', 'num_functions', 'num_events',
                             'has_fallback', 'has_receive', 'is_scam']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_records)
            
            print(f"\nСохранено {len(all_records)} контрактов")
            
            scam = sum(1 for d in all_records if int(d['is_scam']) == 1)
            safe = len(all_records) - scam
            print(f"   Scam: {scam}, Safe: {safe}")
    else:
        print("Нет новых данных")

if __name__ == "__main__":
    collect_dataset()