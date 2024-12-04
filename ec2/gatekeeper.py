# gatekeeper.py

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Trusted Host IP
TRUSTED_HOST_IP = "54.123.45.71"  # Replace with actual Trusted Host IP


@app.route('/api', methods=['POST'])
def api():
    data = request.get_json()

    # Simple validation example
    if not data or 'action' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    # Forward to Trusted Host
    response = requests.post(f"http://{TRUSTED_HOST_IP}:5002/process", json=data)
    return jsonify(response.json()), response.status_code


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)