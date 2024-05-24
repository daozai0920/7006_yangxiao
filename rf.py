import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score
import joblib


data = pd.read_csv("dataset_small.csv")

missing_values=data.isnull().sum()
missing_values.count()
#print(missing_values)

duplicate_rows=data.duplicated().sum()
print(duplicate_rows)

unique_rows = len(data) - duplicate_rows

cleaned_data = data.drop_duplicates()
cleaned_data = data.dropna()

X = cleaned_data.drop('phishing', axis=1)
y = cleaned_data['phishing']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_scaled = pd.DataFrame(X_scaled, columns=X.columns)

# Feature selection
tree_clf = ExtraTreesClassifier(n_estimators=100)
tree_clf.fit(X_scaled, y)
feature_importances = tree_clf.feature_importances_
features = X_scaled.columns
importances_df = pd.DataFrame({'Features': features, 'Importance': feature_importances})
final_features = importances_df[importances_df['Importance'] > 0.02]
# print("Features with importance > 0.02:", final_features)
selected_features = final_features['Features'].tolist()
# Feature transformation
final_features_data = X_scaled[final_features['Features'].tolist()]
pca = PCA(n_components=15)
X_pca = pca.fit_transform(final_features_data)

joblib.dump(scaler, 'pkl/scaler.pkl')
joblib.dump(pca, 'pkl/pca.pkl')
joblib.dump(selected_features, 'pkl/selected_features.pkl')

X_train, X_test, y_train, y_test = train_test_split(X_pca, y, test_size=0.2, random_state=42)
# Random Forest

# Rerun Random Forest Classifier as per Chenxi's code
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)
# print("Accuracy of Random Forest Classifier is:", rf_model.score(X_test, y_test))
# y_pred_rf = rf_model.predict(X_test)
#rf_conf_matrix = confusion_matrix(y_test, y_pred_rf)


import pickle
filename = 'pkl/RF_model.sav'
pickle.dump(rf_model,open(filename,'wb'))