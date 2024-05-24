from FeatureExtraction import reformat
import joblib
import pandas as pd
from FeatureExtraction import pca
import pickle
#url="https://82hp.com/?shiny"  #Phishing website
url="https://google.com"
#new_data_pca=pca(url)
model = pickle.load(open('pkl/RF_model.sav', 'rb'))
scaler = joblib.load('pkl/scaler.pkl')
pca = joblib.load('pkl/pca.pkl')
selected_features = joblib.load('pkl/selected_features.pkl')
new_data = reformat(url)
new_data_scaled = scaler.transform(new_data)
new_data_scaled = pd.DataFrame(new_data_scaled, columns=new_data.columns)
new_data_selected = new_data_scaled[selected_features]
new_data_pca = pca.transform(new_data_selected)
predictions = model.predict(new_data_pca)

if predictions[0] == 1:
    result = 'Phishing website: %s' % predictions
else:
    result = 'Not a phishing website: %s' % predictions
print(result)