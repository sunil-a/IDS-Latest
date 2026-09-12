from flask import Flask, render_template, request, jsonify
import numpy as np
import pickle
import os

app = Flask(__name__)

# Load the pre-trained model
model_path = 'randomForestModel.pkl'
if os.path.exists(model_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
else:
    raise FileNotFoundError(f"Model file not found at {model_path}")

def analyze_traffic_patterns(feature_vector):
    """Analyze traffic patterns for suspicious behavior"""
    alerts = []
    
    # Check for suspicious patterns
    if feature_vector['duration'] > 0.8:
        alerts.append("Unusually long connection duration detected")
    
    if feature_vector['wrong_fragment'] > 0:
        alerts.append("Fragmentation anomaly detected")
        
    if feature_vector['urgent'] > 0.5:
        alerts.append("High number of urgent packets")
        
    if feature_vector['hot'] > 0.7:
        alerts.append("High number of hot indicators")
        
    if feature_vector['src_bytes'] > 0.9:
        alerts.append("Unusually high source bytes")
        
    return alerts

def get_attack_probability(feature_vector):
    """Calculate attack probability based on key indicators"""
    risk_score = 0
    
    # Weight different factors
    risk_score += feature_vector['hot'] * 0.3
    risk_score += feature_vector['wrong_fragment'] * 0.2
    risk_score += feature_vector['urgent'] * 0.15
    risk_score += feature_vector['duration'] * 0.1
    risk_score += (feature_vector['src_bytes'] + feature_vector['dst_bytes'])/2 * 0.25
    
    return min(risk_score, 1.0)  # Normalize to 0-1

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Initialize feature vector with realistic default values
        feature_vector = {
            'duration': float(request.form['feature_0']),
            'protocol_type': float(request.form['feature_1']),
            'flag': float(request.form['feature_3']),
            'src_bytes': float(request.form['feature_4']),
            'dst_bytes': float(request.form['feature_5']),
            'land': float(request.form['feature_6']),
            'wrong_fragment': float(request.form['feature_7']),
            'urgent': float(request.form['feature_8']),
            'hot': float(request.form['feature_9']),
            'num_failed_logins': 0.1,  # Changed from 0.0 to more realistic values
            'logged_in': 1.0,
            'num_compromised': 0.0,
            'root_shell': 0.0,
            'su_attempted': 0.0,
            'num_file_creations': 0.2,
            'num_shells': 0.0,
            'num_access_files': 0.1,
            'num_outbound_cmds': 0.0,
            'is_host_login': 0.0,
            'is_guest_login': 1.0,
            'count': 0.3,
            'srv_count': 0.3,
            'serror_rate': 0.0,
            'rerror_rate': 0.0,
            'same_srv_rate': 0.8,
            'diff_srv_rate': 0.2,
            'srv_diff_host_rate': 0.1,
            'dst_host_count': 0.5,
            'dst_host_srv_count': 0.5,
            'dst_host_diff_srv_rate': 0.2,
            'dst_host_same_src_port_rate': 0.7,
            'dst_host_srv_diff_host_rate': 0.1
        }

        # Convert dictionary to list in the correct order
        input_array = np.array(list(feature_vector.values())).reshape(1, -1)
        
        # Make prediction
        prediction = model.predict(input_array)
        prediction_proba = model.predict_proba(input_array)[0]
        
        # Analyze traffic patterns
        alerts = analyze_traffic_patterns(feature_vector)
        
        # Calculate risk score
        risk_score = get_attack_probability(feature_vector)
        
        # Determine traffic status
        if risk_score > 0.7 or len(alerts) >= 3:
            result = 'High Risk - Attack Detected'
            risk_level = 'high'
        elif risk_score > 0.4 or len(alerts) >= 1:
            result = 'Medium Risk - Suspicious Traffic'
            risk_level = 'medium'
        else:
            result = 'Low Risk - Normal Traffic'
            risk_level = 'low'
        
        return render_template('result.html',
                             prediction=result,
                             risk_level=risk_level,
                             risk_score=f"{risk_score:.2%}",
                             alerts=alerts,
                             input_data=feature_vector,
                             prediction_proba=f"{max(prediction_proba):.2%}")
    
    except Exception as e:
        return render_template('error.html', error=str(e))

if __name__ == '__main__':
    app.run(debug=True)