import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score

# -----------------------------
# Load Dataset
# -----------------------------
dataset_path = "dataset/phishing_email.csv"

df = pd.read_csv(dataset_path)

print("Dataset Loaded Successfully")
print(df.head())

# -----------------------------
# Features & Labels
# -----------------------------
X = df["text_combined"]
y = df["label"]

# -----------------------------
# Train/Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------
# TF-IDF Vectorizer
# -----------------------------
vectorizer = TfidfVectorizer(stop_words="english")

X_train_vector = vectorizer.fit_transform(X_train)
X_test_vector = vectorizer.transform(X_test)

# -----------------------------
# Train Model
# -----------------------------
model = MultinomialNB()

model.fit(X_train_vector, y_train)

# -----------------------------
# Accuracy
# -----------------------------
prediction = model.predict(X_test_vector)

accuracy = accuracy_score(y_test, prediction)

print(f"Model Accuracy : {accuracy * 100:.2f}%")

# -----------------------------
# Create Model Folder
# -----------------------------
os.makedirs("model", exist_ok=True)

# -----------------------------
# Save Model
# -----------------------------
joblib.dump(model, "model/phishing_model.pkl")
joblib.dump(vectorizer, "model/vectorizer.pkl")

print("Model Saved Successfully")
print("Files Created:")
print("model/phishing_model.pkl")
print("model/vectorizer.pkl")