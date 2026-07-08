import time
import joblib
import pandas as pd

file_path = "/content/drive/MyDrive/Enterprise_NIDS/UNSW_NB15_test_split.csv"
Intrusion_test = pd.read_csv(file_path)

try:
  lgb_path = '/content/drive/MyDrive/Enterprise_NIDS/Multiclass_lightgbm_model.pkl'
  label_path = '/content/drive/MyDrive/Enterprise_NIDS/label_encoder.pkl'
  model=joblib.load(lgb_path)
  label_encoder=joblib.load(label_path)
  print("Model and label encoder successfully loaded.")
except FileNotFoundError:
  print("Error: Could not find 'multiclass_lightgbm_model.pkl' or 'label_encoder.pkl'.")
  print("Run your training script first to generate these files.")
  exit()

if "id" in Intrusion_test.columns:
  Intrusion_test.drop(columns=["id"],inplace=True)
X_stream_source=Intrusion_test.drop(columns=["attack_cat","label"],errors="ignore")
ground_truth=Intrusion_test["attack_cat"]
categorial_cols=["proto","service","state"]
for col in categorial_cols:
  X_stream_source[col]=(
      X_stream_source[col].astype(str).fillna("missing").astype("category")
  )
def network_packet_stream (delay_seconds=1.0):
    print(f"\nStarting Stream (Interval :{delay_seconds}s) Control+c to stop")
    for index in range(min(100, len(X_stream_source))):
      packet_row=X_stream_source.iloc[[index]]
      actual_attack_name=ground_truth.iloc[index]
      numeric_pred=model.predict(packet_row)[0]
      predicted_attack_name=label_encoder.inverse_transform([numeric_pred])[0]

      dashboard_payload={
          "packet_id":index,
          "protocol":packet_row["proto"].values[0],
          "service":packet_row["service"].values[0],
          "duration":float(packet_row["dur"].values[0]),
          "source_bytes":int(packet_row["sbytes"].values[0]),
          "destination_bytes":int(packet_row["dbytes"].values[0]),
          "predicted_status":predicted_attack_name,
          "actual_status":actual_attack_name,
          "alert_triggered": "SAFE"
          if predicted_attack_name=="Normal"
          else "Alert"
      }
      yield dashboard_payload
      time.sleep(delay_seconds)
if __name__=="__main__":
  for packet in network_packet_stream(delay_seconds=0.1):
    print(
        f"[{packet['alert_triggered']}] Packet ID: {packet['packet_id']} | "
        f"Proto: {packet['protocol']} | Dur : {packet['duration']}s | "
        f"Predicted: {packet['predicted_status']} (Actual: {packet['actual_status']})"
    )
