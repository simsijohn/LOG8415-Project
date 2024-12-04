# proxy.py

from flask import Flask, request, jsonify
import requests
import random

app = Flask(__name__)

# List of Worker IPs (to be updated dynamically or fetched from config)
WORKER_IPS = ["54.123.45.68", "54.123.45.69"]  # Replace with actual IPs

# Manager IP
MANAGER_IP = "54.123.45.67"  # Replace with actual Manager IP

@app.route('/read', methods=['GET'])
def read():
    worker_ip = random.choice(WORKER_IPS)
    response = requests.get(f"http://{worker_ip}:5001/read")
    return jsonify(response.json()), response.status_code

@app.route('/write', methods=['POST'])
def write():
    data = request.get_json()
    response = requests.post(f"http://{MANAGER_IP}:5001/write", json=data)
    return jsonify(response.json()), response.status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)