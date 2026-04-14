import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

df = pd.read_csv(r'C:\Users\home_\Projects\Orbis\dataset.csv')
print(f"Размер датасета: {df.shape}")
print(f"Scam: {df['is_scam'].sum()}, Safe: {len(df) - df['is_scam'].sum()}")

feature_cols = ['has_mint', 'has_owner', 'has_tax', 'has_pause', 
                'has_blacklist', 'has_upgrade', 'has_selfdestruct', 
                'num_functions', 'num_events', 'has_fallback', 'has_receive']

X = df[feature_cols]
y = df['is_scam']

X_train,X_test, y_train, y_test = train_test_split(X,y, test_size=0.2, random_state=1337)

model = RandomForestClassifier(n_estimators=100, random_state=1337)
model.fit(X_train,y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test,y_pred)
print(f"\n Точность модели: {accuracy:.1%}")

print("\n Отчет по классам:")
print(classification_report(y_test,y_pred))

importance = pd.DataFrame({
    'feature': feature_cols,
    'importance': model.feature_importances_
}).sort_values('importance',ascending=False)
print(f"\n Важность фич:")
print(importance)

joblib.dump(model, 'scam_model.pkl')

