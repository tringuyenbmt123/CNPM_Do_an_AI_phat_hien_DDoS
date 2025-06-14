import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

features = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Flow Bytes/s",
    "Flow Packets/s",
    "FWD Header Length",
    "BWD Header Length",
    "Bwd Packet Length Mean",
    "Init_Win_Bytes_Forward",
    "Init_Win_Bytes_Backward",
    "Min_Seg_Size_Forward",
    "SimillarHTTP"
]

label_col = "Label"

df = pd.read_csv("/data/DrDoS_UDP.csv")
df = df[features + ["Label"]]
X = df[features]
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
param_grid = {
    "n_estimators": [50, 100, 150],
    "max_depth": [5, 10, None],
}
grid_search = GridSearchCV(
    estimator=RandomForestClassifier(random_state=42),
    param_grid=param_grid,
    cv=5,
    scoring="accuracy",
    n_jobs=-1,
    verbose=1
)
grid_search.fit(X_train, y_train)

best_model = grid_search.best_estimator_

y_pred = best_model.predict(X_test)

print("\nBest Parameters:", grid_search.best_params_)
print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print(f"Recall   : {recall_score(y_test, y_pred):.4f}")
print(f"F1-Score : {f1_score(y_test, y_pred):.4f}")

joblib.dump(best_model, "random_forest_DrDoS_UDP.pkl")
print("Mô hình đã được lưu: random_forest_DrDoS_UDP.pkl")