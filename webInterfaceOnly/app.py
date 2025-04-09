from flask import Flask, render_template, request, jsonify, session, send_file
from flask_session import Session
import os
from dotenv import load_dotenv
import mitre
import graph
import io
import base64
import logging
import aiohttp
import asyncio
import json

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
ENABLE_TABLETOP = os.getenv("ENABLE_TABLETOP", "false").lower() == "true"
OLLAMA_URL = os.getenv("OLLAMA_URL")

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

def process_query(query_type, method=None, query=None):
    """Process user queries and return formatted responses."""
    query_type = query_type.lower()
    
    if query_type == 'ttp':
        if not method or method not in ['id', 'search', 'detail']:
            return "Invalid method for TTP. Use 'id', 'search', or 'detail'."
        if not query:
            return "Please provide a query for TTP."
        if method == 'id':
            result = mitre.search_by_ttp_id(query)
            if not result:
                return f"No technique found for: {query.upper()}"
            return '\n'.join(f"{res['ttp_id']} - {res['name']}" for res in result)
        elif method == 'search':
            result = mitre.search_by_name_or_description(query)
            if not result:
                return f"No techniques found for: {query}"
            return '\n'.join(f"{res['ttp_id']} - {res['name']}" for res in result)
        else:  # detail
            result = mitre.get_technique_details(query)
            if not result:
                return f"No technique found for: {query.upper()}"
            return f"TTP ID: {result['ttp_id']}\nName: {result['name']}\nDescription: {result['description']}"

    elif query_type == 'group':
        if not query:
            return "Please provide a query for group."
        results = mitre.search_groups(query)
        if not results:
            return f"No groups found for query: {query}"
        return '\n'.join(f"Group ID: {r['group_id']}\nName: {r['name']}\nDescription: {r['description']}" for r in results)

    elif query_type == 'software':
        if not query:
            return "Please provide a query for software."
        results = mitre.search_software(query)
        if not results:
            return f"No software found for query: {query}"
        return '\n'.join(f"Software ID: {r['software_id']}\nName: {r['name']}\nDescription: {r['description']}" for r in results)

    elif query_type == 'campaign':
        if not query:
            return "Please provide a query for campaign."
        results = mitre.search_campaigns(query)
        if not results:
            return f"No campaigns found for query: {query}"
        return '\n'.join(f"Campaign ID: {r['campaign_id']}\nName: {r['name']}\nDescription: {r['description']}" for r in results)

    elif query_type == 'graph':
        if not query:
            return "Please provide a query for graph."
        query = query.upper()
        img_buffer = graph.generate_graph(query)
        if img_buffer:
            img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
            return {"text": f"Graph for {query}", "image": img_data}
        return f"No linked items found for {query}"

    elif query_type == 'recommend':
        if not query:
            return "Please provide a query for recommendations."
        query = query.upper()
        entities, _ = graph.fetch_linked_entities(query)
        ttps = [e['attck_id'] for e in entities.values() if e['type'] == 'technique']
        if not ttps:
            return f"No techniques found for {query}."
        recommendations = mitre.recommend_log_sources(ttps)
        if "error" in recommendations:
            return recommendations["error"]
        msg = (f"Log Source Recommendations for {query}\n"
               f"Queried TTPs: {recommendations['total_ttps']} | Covered: {recommendations['covered_ttps']} "
               f"({recommendations['coverage_percentage']:.1f}%)\n"
               "Log Sources:\n")
        for source_name, details in recommendations["log_sources"].items():
            ttps_str = ", ".join(details["covered_ttps"][:5])
            if len(details["covered_ttps"]) > 5:
                ttps_str += f" (+{len(details['covered_ttps']) - 5} more)"
            msg += f"- {source_name} (Quality: {details['quality']}/3, Platforms: {details['platforms']})\n  Covered: {ttps_str}\n"
        if recommendations["blind_spots"]:
            blind_spots = ", ".join(recommendations["blind_spots"][:5])
            if len(recommendations["blind_spots"]) > 5:
                blind_spots += f" (+{len(recommendations['blind_spots']) - 5} more)"
            msg += f"Blind Spots: {blind_spots}"
        return msg

    elif query_type == 'create-tabletop' and ENABLE_TABLETOP:
        if not OLLAMA_URL:
            return "Tabletop creation requires Ollama, but OLLAMA_URL is not configured."
        if 'tabletop_step' not in session:
            session['tabletop_step'] = 1
            session['tabletop_data'] = {}
            session.modified = True
            return "Starting tabletop exercise creation.\nPlease specify the day of the week and time of day (e.g., 'Monday morning'):"
        return "Please continue the tabletop process in the next message."

    else:
        return f"Invalid query type or command disabled. Available types: ttp, group, software, campaign, graph, recommend{' create-tabletop' if ENABLE_TABLETOP else ''}."

async def query_ollama(prompt):
    """Query the Ollama API and return the response."""
    async with aiohttp.ClientSession() as session:
        payload = {
            "model": "phi3",  # Adjust model as needed
            "prompt": prompt,
            "stream": False
        }
        try:
            async with session.post(f"{OLLAMA_URL}/api/generate", json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get("response", "No response from Ollama.")
                else:
                    logger.error(f"Ollama API error: {response.status}")
                    return f"Error querying Ollama: {response.status}"
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
            return f"Failed to connect to Ollama: {str(e)}"

def fetch_mitre_details(scenario_type):
    """Fetch MITRE ATT&CK details for the scenario type if it matches a known entity."""
    scenario_type_lower = scenario_type.lower()
    mitre_data = {}

    # Check if it's a TTP (e.g., T1059)
    if mitre.validate_ttp_id(scenario_type):
        details = mitre.get_technique_details(scenario_type)
        if details:
            mitre_data['type'] = 'technique'
            mitre_data['details'] = details
            return mitre_data

    # Check if it's a group (e.g., G0007 or APT28)
    if mitre.validate_group_id(scenario_type):
        groups = mitre.search_groups(scenario_type)
        if groups:
            mitre_data['type'] = 'group'
            mitre_data['details'] = groups[0]
            return mitre_data
    else:
        groups = mitre.search_groups(scenario_type)
        if groups:
            mitre_data['type'] = 'group'
            mitre_data['details'] = groups[0]
            return mitre_data

    # Check if it's a software (e.g., S0002)
    if mitre.validate_id(scenario_type, 'S'):
        software = mitre.search_software(scenario_type)
        if software:
            mitre_data['type'] = 'software'
            mitre_data['details'] = software[0]
            return mitre_data
    else:
        software = mitre.search_software(scenario_type)
        if software:
            mitre_data['type'] = 'software'
            mitre_data['details'] = software[0]
            return mitre_data

    # Check if it's a campaign (e.g., C0001)
    if mitre.validate_id(scenario_type, 'C'):
        campaigns = mitre.search_campaigns(scenario_type)
        if campaigns:
            mitre_data['type'] = 'campaign'
            mitre_data['details'] = campaigns[0]
            return mitre_data
    else:
        campaigns = mitre.search_campaigns(scenario_type)
        if campaigns:
            mitre_data['type'] = 'campaign'
            mitre_data['details'] = campaigns[0]
            return mitre_data

    # If no match, assume generic scenario (e.g., ransomware, data breach)
    return {'type': 'generic', 'details': scenario_type}

def handle_tabletop_input(user_input):
    """Handle multi-step tabletop creation input."""
    step = session.get('tabletop_step', 1)
    data = session.get('tabletop_data', {})

    if step == 1:
        data['day_time'] = user_input
        session['tabletop_step'] = 2
        session['tabletop_data'] = data
        session.modified = True
        return "Please specify the scenario type (e.g., 'ransomware', 'T1059', 'G0007', 'S0002', 'C0001'):"
    
    elif step == 2:
        data['scenario_type'] = user_input
        mitre_data = fetch_mitre_details(user_input)
        data['mitre_data'] = mitre_data
        session.pop('tabletop_step', None)
        session['tabletop_data'] = data  # Keep data for download
        session.modified = True
        result = asyncio.run(generate_tabletop_document(data))
        session['conversation'].append({'sender': 'bot', 'text': result + "\n\n[Download Markdown](#download)"})
        return result

async def generate_tabletop_document(data):
    """Generate a tabletop document using Ollama with MITRE ATT&CK data."""
    mitre_data = data.get('mitre_data', {})
    scenario_details = ""

    if mitre_data['type'] == 'technique':
        d = mitre_data['details']
        scenario_details = (
            f"This scenario involves the MITRE ATT&CK technique {d['ttp_id']} ({d['name']}).\n"
            f"Description: {d['description']}"
        )
    elif mitre_data['type'] == 'group':
        d = mitre_data['details']
        scenario_details = (
            f"This scenario involves the MITRE ATT&CK group {d['group_id']} ({d['name']}).\n"
            f"Description: {d['description']}"
        )
    elif mitre_data['type'] == 'software':
        d = mitre_data['details']
        scenario_details = (
            f"This scenario involves the MITRE ATT&CK software {d['software_id']} ({d['name']}).\n"
            f"Description: {d['description']}"
        )
    elif mitre_data['type'] == 'campaign':
        d = mitre_data['details']
        scenario_details = (
            f"This scenario involves the MITRE ATT&CK campaign {d['campaign_id']} ({d['name']}).\n"
            f"Description: {d['description']}"
        )
    else:
        scenario_details = f"This scenario involves a generic {data['scenario_type']} event."

    prompt = (
        f"Generate a tabletop exercise document in Markdown format for a cybersecurity scenario. "
        f"The exercise is scheduled for {data['day_time']} and involves the following scenario:\n"
        f"{scenario_details}\n"
        f"Include sections for an introduction, objectives, scenario description, and discussion questions."
    )
    response = await query_ollama(prompt)
    return response

@app.route('/')
def index():
    if 'conversation' not in session:
        session['conversation'] = []
    return render_template('index.html', conversation=session['conversation'], enable_tabletop=ENABLE_TABLETOP)

@app.route('/send', methods=['POST'])
def send_message():
    user_input = request.form['message'].strip()
    if not user_input:
        return jsonify({'response': 'Please enter a message.'})

    if 'conversation' not in session:
        session['conversation'] = []

    session['conversation'].append({'sender': 'user', 'text': user_input})
    session.modified = True

    if 'tabletop_step' in session and ENABLE_TABLETOP:
        response = handle_tabletop_input(user_input)
    else:
        parts = user_input.split(maxsplit=2)
        query_type = parts[0].lower()
        method = parts[1] if len(parts) > 2 and query_type == 'ttp' else None
        query = parts[2] if len(parts) > 2 else parts[1] if len(parts) > 1 else None if query_type != 'create-tabletop' else ''
        response = process_query(query_type, method, query)

    if isinstance(response, dict) and 'image' in response:
        session['conversation'].append({'sender': 'bot', 'text': response['text'], 'image': response['image']})
    else:
        session['conversation'].append({'sender': 'bot', 'text': response})
    session.modified = True

    return jsonify({'response': response})

@app.route('/clear', methods=['POST'])
def clear_conversation():
    session['conversation'] = []
    session.pop('tabletop_step', None)
    session.pop('tabletop_data', None)
    session.modified = True
    return jsonify({'status': 'cleared'})

@app.route('/download', methods=['GET'])
def download_tabletop():
    if 'tabletop_data' not in session or 'mitre_data' not in session['tabletop_data']:
        return "No tabletop document available for download.", 404
    
    data = session['tabletop_data']
    document = asyncio.run(generate_tabletop_document(data))
    buffer = io.BytesIO(document.encode('utf-8'))
    buffer.seek(0)
    filename = f"tabletop_{data['day_time'].replace(' ', '_')}_{data['scenario_type'].replace(' ', '_')}.md"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='text/markdown')

if __name__ == '__main__':
    logger.info(f"Tabletop command is {'enabled' if ENABLE_TABLETOP else 'disabled'}")
    if ENABLE_TABLETOP and not OLLAMA_URL:
        logger.warning("OLLAMA_URL not set; tabletop creation will fail.")
    app.run(debug=True, host='0.0.0.0', port=5000)