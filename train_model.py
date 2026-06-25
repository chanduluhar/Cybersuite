import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib
import os
from ml_engine import URLFeatureExtractor

def generate_synthetic_data(n_samples=2000):
    """Generates a synthetic dataset for phishing URLs based on common features."""
    data = []
    for _ in range(n_samples):
        is_phishing = np.random.choice([0, 1])
        
        if is_phishing:
            url = f"http://{''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), 15))}.com/{''.join(np.random.choice(list('abcdef-'), 20))}"
            if np.random.rand() > 0.5: url = "http://123.45.67.89/login"
        else:
            url = f"https://www.google.com/search?q={''.join(np.random.choice(list('abcdef'), 5))}"
            
        features = URLFeatureExtractor.get_features(url)
        features['label'] = is_phishing
        data.append(features)
        
    return pd.DataFrame(data)

def train():
    print("Generating training data...")
    df = generate_synthetic_data()
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest model...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    # Save artifacts
    if not os.path.exists('models'):
        os.makedirs('models')
        
    joblib.dump(model, 'models/phishing_model.pkl')
    joblib.dump(scaler, 'models/scaler.pkl')
    joblib.dump(list(X.columns), 'models/feature_names.pkl')
    
    print(f"Model trained. Accuracy: {model.score(scaler.transform(X_test), y_test):.2f}")
    print("Model saved to models/phishing_model.pkl")

if __name__ == '__main__':
    train()
