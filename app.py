# app.py - Main Flask application
from flask import Flask, render_template, request, jsonify
import requests
import json
from reportlab.lib import pdfgen  # For PDF generation
from datetime import datetime

app = Flask(__name__)

# Configuration
OLLAMA_SERVER = "http://10.5.10.104:80"
MISP_SERVER = "https://misp.lab"
MISP_API_KEY = "your-misp-api-key"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/create_tabletop', methods=['POST'])
def create_tabletop():
    # Get form data
    data = request.json
    ip_ranges = data['ip_ranges']
    departments = data['departments']
    technologies = data['technologies']
    incident_time = data['incident_time']
    
    # Step 1: Either get manual TTPs or query MISP
    if data.get('manual_ttps'):
        ttps = data['manual_ttps']
        description = data['description']
    else:
        # Query MISP for threats
        misp_response = query_misp(ip_ranges, technologies)
        # This would normally be a separate selection step
        selected_threat = misp_response[0]  # Simplified for example
        ttps = query_misp_ttps(selected_threat['id'])

    # Generate narrative using Ollama
    narrative = generate_narrative_ollama({
        'ip_ranges': ip_ranges,
        'departments': departments,
        'technologies': technologies,
        'incident_time': incident_time,
        'ttps': ttps
    })

    # Generate simulated logs
    logs = generate_simulated_logs(technologies, ttps)

    # Save files
    output = {
        'metadata': {
            'created': datetime.now().isoformat(),
            'incident_time': incident_time
        },
        'input_data': data,
        'ttps': ttps,
        'narrative': narrative,
        'logs': logs
    }
    
    # Save JSON
    filename = f"tabletop_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    with open(f"{filename}.json", 'w') as f:
        json.dump(output, f)
    
    # Generate and save PDF
    generate_pdf(filename, output)
    
    return jsonify({'status': 'success', 'filename': filename})

def query_misp(ip_ranges, technologies):
    headers = {'Authorization': MISP_API_KEY}
    query = {
        'ip_ranges': ip_ranges,
        'technologies': technologies
    }
    response = requests.post(f"{MISP_SERVER}/events/search", 
                           json=query, 
                           headers=headers,
                           verify=False)
    return response.json()

def query_misp_ttps(threat_id):
    headers = {'Authorization': MISP_API_KEY}
    response = requests.get(f"{MISP_SERVER}/attributes/{threat_id}/ttps",
                          headers=headers,
                          verify=False)
    return response.json()

def generate_narrative_ollama(data):
    response = requests.post(f"{OLLAMA_SERVER}/api/generate",
                           json={
                               'prompt': f"Generate a cybersecurity tabletop narrative with: {json.dumps(data)}",
                               'model': 'mistral'  # Or appropriate model
                           })
    return response.json()['text']

def generate_simulated_logs(technologies, ttps):
    # Simple log generator - could be enhanced with Ollama
    logs = []
    for tech in technologies:
        logs.append(f"{tech}: Suspicious activity detected - {ttps[0]}")
    return logs

def generate_pdf(filename, data):
    pdf = pdfgen.Canvas(f"{filename}.pdf")
    y = 800
    pdf.drawString(100, y, "Cybersecurity Tabletop Exercise")
    y -= 20
    pdf.drawString(100, y, f"Created: {data['metadata']['created']}")
    # Add more content...
    pdf.save()

if __name__ == '__main__':
    app.run(debug=True)