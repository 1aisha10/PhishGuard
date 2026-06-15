# ==============================
# PHISHING DETECTION PROJECT
# ==============================

import pandas as pd
import numpy as np
import re
import pickle
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report

# ==============================
# 1. LOAD MAIN DATASET ONLY
# ==============================

df = pd.read_csv(r"D:\phishing web detection\archive\final_dataset.csv")
print("Dataset Loaded")
print(df.shape)

# ==============================
# 2. UNIFY LABELS
# ==============================

label_map = {'bad': 1, 'good': 0, 'phishing': 1, 'legitimate': 0}

def unify_label(val):
    if isinstance(val, str):
        return label_map.get(val.strip().lower(), None)
    return int(val)

df['label'] = df['label'].apply(unify_label)
df.dropna(subset=['label'], inplace=True)
df['label'] = df['label'].astype(int)

print("Label distribution:")
print(df['label'].value_counts())

# ==============================
# 3. SAMPLE 70K BALANCED
# ==============================

df_phishing = df[df['label'] == 1].sample(n=35000, random_state=42)
df_legit    = df[df['label'] == 0].sample(n=35000, random_state=42)
df = pd.concat([df_phishing, df_legit]).sample(frac=1, random_state=42).reset_index(drop=True)

print("Final shape:", df.shape)

# ==============================
# 4. CLEAN & PREPARE FEATURES
# ==============================

df.drop_duplicates(inplace=True)
df.dropna(inplace=True)

# Drop URL column (text, not useful for ML)
if 'url' in df.columns:
    df = df.drop('url', axis=1)

X = df.drop('label', axis=1)
y = df['label']

X = X.select_dtypes(include=[np.number, 'bool'])
X = X.apply(pd.to_numeric, errors='coerce')
X = X.fillna(0)

print("X shape:", X.shape)   # should now show 70k rows, 74 features
print("y shape:", y.shape)

# ==============================
# 5. TRAIN-TEST SPLIT
# ==============================

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ==============================
# 6. TRAIN MODELS
# ==============================

print("\nTraining models...")

lr = LogisticRegression(max_iter=5000,solver='saga')
lr.fit(X_train, y_train)
print("Logistic Regression trained")

rf = RandomForestClassifier(n_estimators=100)
rf.fit(X_train, y_train)
print("Random Forest trained")

svm = SVC()
svm.fit(X_train, y_train)
print("SVM trained")

# ==============================
# 7. EVALUATE
# ==============================

print("\n=== MODEL RESULTS ===")
print("Logistic Regression:", accuracy_score(y_test, lr.predict(X_test)))
print("Random Forest:      ", accuracy_score(y_test, rf.predict(X_test)))
print("SVM:                ", accuracy_score(y_test, svm.predict(X_test)))

print("\nRandom Forest Report:")
print(classification_report(y_test, rf.predict(X_test)))

# ==============================
# 8. SAVE MODEL
# ==============================

pickle.dump(rf, open("phishing_model.pkl", "wb"))
pickle.dump(list(X.columns), open("feature_columns.pkl", "wb"))  # add this line
print("Model saved!")

