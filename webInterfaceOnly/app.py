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
        queries = [q.strip().upper() for q in query.split(',')]
        logger.info(f"Processing queries: {queries}")
        all_ttps = set()
        query_ttp_map = {}
        for q in queries:
            logger.info(f"Fetching TTPs for query: {q}")
            entities, _ = graph.fetch_linked_entities(q)
            if entities:
                ttps = [e['attck_id'] for e in entities.values() if e['type'] == 'technique']
                query_ttp_map[q] = set(ttps)
                all_ttps.update(ttps)
                logger.info(f"TTPs found for {q}: {ttps}")
            else:
                query_ttp_map[q] = set()
                logger.info(f"No entities found for {q}")
        
        if not all_ttps:
            return f"No techniques found for {', '.join(queries)}."
        
        recommendations = mitre.recommend_log_sources(list(all_ttps))
        if "error" in recommendations:
            return recommendations["error"]
        
        msg = f"Log Source Recommendations for {', '.join(queries)}\n\n"
        
        # Individual coverage summary
        msg += "**Coverage Summary:**\n"
        for q in queries:
            ttps = query_ttp_map[q]
            if ttps:
                # Corrected coverage calculation
                covered = sum(1 for ttp in ttps if any(ttp in source["covered_ttps"] for source in recommendations["log_sources"].values()))
                total = len(ttps)
                percent = (covered / total * 100) if total > 0 else 0
                msg += f"- {q}: {covered}/{total} TTPs covered ({percent:.1f}%)\n"
            else:
                msg += f"- {q}: No TTPs found (0%)\n"
        
        # Total coverage
        msg += (f"\n**Total Unique TTPs:** Queried: {recommendations['total_ttps']} | Covered: {recommendations['covered_ttps']} "
                f"({recommendations['total_coverage_percentage']:.1f}%)\n"
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
            msg += f"\nBlind Spots (Uncovered TTPs): {blind_spots}"
        
        return msg
    
    elif query_type == 'group_ttps':
        if not query:
            return "Please provide a query for group TTPs."
        queries = [q.strip().upper() for q in query.split(',')]
        logger.info(f"Processing group_ttps queries: {queries}")
        
        results = mitre.get_group_ttps(queries)
        if "error" in results:
            return results["error"]
        
        # Part 1: Summary of all deduplicated TTPs
        all_ttps = results["all_ttps"]
        msg = "**Summary of All TTPs Used by Queried Groups**\n"
        msg += f"Total Unique TTPs: {len(all_ttps)}\n"
        msg += "\n".join(all_ttps) + "\n\n"
        
        # Part 2: Individual group details (if multiple groups)
        if len(queries) > 1:
            for q in queries:
                ttps = results["group_ttp_map"].get(q, [])
                if ttps:
                    msg += f"**TTPs Used by {q}**\n"
                    msg += f"Total TTPs: {len(ttps)}\n"
                    msg += "\n".join(ttps) + "\n\n"
                else:
                    msg += f"No TTPs found for group **{q}**.\n\n"
        
        return msg.strip()

    elif query_type == 'create-tabletop' and ENABLE_TABLETOP:
        if not OLLAMA_URL:
            return "Tabletop creation requires Ollama, but OLLAMA_URL is not configured."
        session['tabletop_step'] = 'day_time'
        session['tabletop_data'] = {
            'day_time': None,
            'basis_type': None,
            'basis_id': None,
            'technologies': [],
            'num_injects': None,
            'ttps': []
        }
        session.modified = True
        html = '<h2>Tabletop Exercise Creation</h2>'
        html += '<p>Please specify the day of the week and time of day (e.g., "Monday morning"):</p>'
        return html

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
    step = session.get('tabletop_step', 'day_time')
    data = session.get('tabletop_data', {})
    user_input = user_input.strip()

    if step == 'day_time':
        if not user_input:
            return '<p>Please provide a valid day and time (e.g., "Monday morning").</p>'
        data['day_time'] = user_input
        session['tabletop_step'] = 'basis'
        session['tabletop_data'] = data
        session.modified = True
        html = f'<h2>Day and Time Set: {user_input}</h2>'
        html += '<p>Please specify the attack basis: a Group ID (e.g., G0027), Software ID (e.g., S0002), or a general term like "ransomware":</p>'
        return html

    elif step == 'basis':
        if not user_input:
            return '<p>Please provide a valid attack basis.</p>'
        mitre_data = fetch_mitre_details(user_input)
        data['basis_type'] = mitre_data['type']
        if mitre_data['type'] != 'generic':
            data['basis_id'] = mitre_data['details'].get('group_id') or mitre_data['details'].get('software_id') or mitre_data['details'].get('campaign_id') or user_input
            # Fetch TTPs for group or software
            entities, _ = graph.fetch_linked_entities(user_input.upper())
            if entities:
                data['ttps'] = [e['attck_id'] for e in entities.values() if e['type'] == 'technique']
        else:
            data['basis_id'] = user_input
            data['ttps'] = []
        session['tabletop_step'] = 'technologies'
        session['tabletop_data'] = data
        session.modified = True
        html = f'<h2>Attack Basis Set: {user_input}</h2>'
        html += '<p>Please specify the types of technology in the environment (comma-separated, e.g., "Fortinet, Microsoft AD, AWS"):</p>'
        return html

    elif step == 'technologies':
        if not user_input:
            return '<p>Please provide a valid list of technologies.</p>'
        technologies = [t.strip() for t in user_input.split(',') if t.strip()]
        if not technologies:
            return '<p>Please provide at least one technology.</p>'
        data['technologies'] = technologies
        session['tabletop_step'] = 'num_injects'
        session['tabletop_data'] = data
        session.modified = True
        html = '<h2>Technologies Set</h2>'
        html += '<table class="tech-table"><thead><tr><th>Technology</th></tr></thead><tbody>'
        for tech in technologies:
            html += f'<tr><td>{tech}</td></tr>'
        html += '</tbody></table>'
        html += '<p>Please specify the number of injects needed (e.g., 3):</p>'
        return html

    elif step == 'num_injects':
        try:
            num_injects = int(user_input)
            if num_injects <= 0:
                raise ValueError
        except ValueError:
            return '<p>Please provide a valid positive number of injects.</p>'
        data['num_injects'] = num_injects
        session['tabletop_data'] = data
        session.pop('tabletop_step', None)  # End the process
        session.modified = True

        # Generate the document
        result = asyncio.run(generate_tabletop_document(data))
        session['conversation'].append({'sender': 'bot', 'text': result + '<p><a href="/download">Download Markdown</a></p>'})
        html = '<h2>Tabletop Document Generated</h2>'
        html += '<pre>' + result + '</pre>'
        html += '<p><a href="/download">Download Markdown</a></p>'
        return html

    return '<p>Invalid tabletop state. Start a new exercise with <code>create tabletop</code>.</p>'

async def generate_tabletop_document(data):
    """Generate a tabletop document using Ollama with the specified prompt."""
    basis_id = data.get('basis_id', 'TTP Chain')
    prompt = (
        "Generate a tabletop facilitation document in Markdown format for a cybersecurity exercise with the following details:\n"
        f"- Day and Time: {data['day_time']}\n"
        f"- Technologies in Use: {', '.join(data['technologies'])}\n"
        f"- Number of Injects: {data['num_injects']}\n"
        f"- Attack Basis: {data['basis_type']} ({basis_id})\n"
        f"- TTPs Involved: {', '.join(data['ttps']) if data['ttps'] else 'None'}\n\n"
        "Include:\n"
        "1. A short narrative of the event (200-300 words) under a `## Narrative` heading.\n"
        "2. Each inject with a corresponding sample log file from a relevant system (e.g., Fortinet, Microsoft AD) under `## Injects` with subheadings `### Inject X`.\n"
        "3. Facilitation tips under a `## Facilitation Tips` heading.\n"
        "Use Markdown syntax (e.g., `##`, `###`, `-` for lists, ``` for code blocks)."
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
        parts = user_input.split(maxsplit=1)
        query_type = parts[0].lower()
        query = parts[1] if len(parts) > 1 else None

        if query_type == 'ttp':
            ttp_parts = query.split(maxsplit=1) if query else [None, None]
            method = ttp_parts[0].lower() if ttp_parts[0] else None
            query = ttp_parts[1] if len(ttp_parts) > 1 else None
            if method not in ['id', 'search', 'detail']:
                response = "Invalid method for TTP. Use 'id', 'search', or 'detail'."
            else:
                response = process_query(query_type, method, query)
        elif query_type == 'create':
            create_parts = query.split(maxsplit=1) if query else [None, None]
            method = create_parts[0].lower() if create_parts[0] else None
            query = create_parts[1] if len(create_parts) > 1 else None
            if method != 'tabletop':
                response = "Invalid create command. Use 'create tabletop'."
            else:
                response = process_query(query_type, method, query)
        else:
            response = process_query(query_type, None, query)

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