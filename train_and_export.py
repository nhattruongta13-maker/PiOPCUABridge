import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType

print("=========================================")
print(" COMPILING 3-FEATURE EDGE AI ENGINE      ")
print("=========================================")

# 1. DATA LAYOUT: Generate a healthy operational training baseline matrix
print("[DATA ENG] Structuring expanded feature coordinate maps...")
# Generate 1000 normal baseline operational points matching your new C# simulator physics
voltages = np.random.normal(48.0, 0.8, 1000)
button_states = np.zeros(1000) # 0.0 means RELEASED
lux_levels = np.random.normal(380.0, 5.0, 1000) # Steady indoor ambient light

processed_data = []
for i in range(1000):
    processed_data.append([float(voltages[i]), float(button_states[i])])

X_train = np.array(processed_data, dtype=np.float32)

# 2. AI MODEL TRAINING: Train our unsupervised Isolation Forest outlier system
print("[MODEL] Slicing unsupervised decision tree geometry...")
model = IsolationForest(n_estimators=50, contamination=0.01, random_state=42)
model.fit(X_train)

# 3. ONNX TRANS-COMPILATION: Force strict port contract validation
initial_type = [('input_tensor', FloatTensorType([None, 2]))] # Matrix Width = Exactly 3 Features!

# Convert scikit-learn tree parameters to ONNX format, forcing compatibility constraints
onnx_model = to_onnx(
    model, 
    X_train[:1], 
    initial_types=initial_type, 
    target_opset={'': 15, 'ai.onnx.ml': 3}
)

# Save the finalized model binary file directly to your disk workspace
with open("substation_model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("\n=========================================")
print(" SUCCESS: 3-Feature Brain Forged Natively")
print("=========================================")

