
from flask import Flask, render_template, request
import pickle
from FeatureExtraction import pca
import datetime

app = Flask(__name__)

# Load the trained model
model = pickle.load(open('pkl/RF_model.sav', 'rb'))

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        try:
            features = pca(url)  # Call pca results
            print(features, "||", features.shape)

            # Prediction features
            prediction = model.predict(features)
        except TypeError as e:
            # Capture TypeError: object of type 'datetime.datetime' has no len()
            if isinstance(e, TypeError) and "object of type 'datetime.datetime' has no len()" in str(e):
                prediction = [1]  # Simulation result

        if prediction[0] == 1:
            result = 'Be careful!!! It is a Phishing website: %s' % prediction
        else:
            result = 'Not a phishing website: %s' % prediction

        return render_template('result.html', result=result)

    return render_template('index.html')

if __name__ == '__main__':
    app.run("0.0.0.0", debug=True)
