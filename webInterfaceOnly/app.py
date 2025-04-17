from flask import Flask, render_template, request, jsonify, session, send_file, redirect, url_for, flash
from flask_session import Session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
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
import datetime
import mysql.connector
import bcrypt
import re

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
ENABLE_TABLETOP = os.getenv("ENABLE_TABLETOP", "false").lower() == "true"
OLLAMA_URL = os.getenv("OLLAMA_URL")
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB = os.getenv("DB")

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

# Database connection
def connect_to_db():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB
    )

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'])
        return None
    except Exception as e:
        logger.error(f"Error loading user: {e}")
        return None

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
        
        msg += "**Coverage Summary:**\n"
        for q in queries:
            ttps = query_ttp_map[q]
            if ttps:
                covered = sum(1 for ttp in ttps if any(ttp in source["covered_ttps"] for source in recommendations["log_sources"].values()))
                total = len(ttps)
                percent = (covered / total * 100) if total > 0 else 0
                msg += f"- {q}: {covered}/{total} TTPs covered ({percent:.1f}%)\n"
            else:
                msg += f"- {q}: No TTPs found (0%)\n"
        
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
        
        all_ttps = results["all_ttps"]
        msg = "**Summary of All TTPs Used by Queried Groups**\n"
        msg += f"Total Unique TTPs: {len(all_ttps)}\n"
        msg += "\n".join(all_ttps) + "\n\n"
        
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
            "model": "phi3:latest",
            "prompt": prompt,
            "stream": False
        }
        endpoint = f"{OLLAMA_URL}/api/generate"
        logger.info(f"Querying Ollama at {endpoint} with model phi3:latest")
        try:
            async with session.post(endpoint, json=payload) as response:
                logger.info(f"Ollama response status: {response.status}")
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

    if mitre.validate_ttp_id(scenario_type):
        details = mitre.get_technique_details(scenario_type)
        if details:
            mitre_data['type'] = 'technique'
            mitre_data['details'] = details
            return mitre_data

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

    return {'type': 'generic', 'details': scenario_type}

async def generate_tabletop_document(data):
    """Generate a tabletop exercise document with inline JSON log entries and a complete JSON version."""
    try:
        base_time = datetime.datetime.now().replace(
            hour=9, minute=0, second=0, microsecond=0
        ).isoformat() + "Z"

        ttps_str = ', '.join(data['ttps']) if data['ttps'] else 'None'
        prompt = f"""
Generate a tabletop exercise document in Markdown format with the EXACT structure below, based on these details:
- **Day and Time**: {data['day_time']}
- **Basis**: {data['basis_id']} ({data['basis_type']})
- **Technologies**: {', '.join(data['technologies'])}
- **Number of Injects**: {data['num_injects']}
- **TTPs**: {ttps_str}

Use this precise structure, with no deviations:
# Narrative
[Provide a detailed scenario context, at least 3 sentences, describing the environment and threat based on the basis and technologies.]

{"".join(f"""
# Inject {i}: [Unique Title]
[Describe the event, 2-3 sentences, aligned with the TTPs or basis/technologies.]
**Objective**: [One sentence stating the participant objective, e.g., "Detect the suspicious activity."]
**Log Evidence**
```json
{{
  "timestamp": "[ISO timestamp, starting at {base_time}, increment by 5 minutes per inject]",
  "event": "[Brief event description, matching the inject]",
  "source": "[Relevant source, e.g., IP, user, or system]",
  "details": "[Context-specific details, e.g., command executed or file accessed]"
}}
```""" for i in range(1, data['num_injects'] + 1))}

# Facilitation Tips
[Provide guidance for running the exercise, at least 3 sentences, including tips for facilitators.]

Rules:
- Use the exact headings: "# Narrative", "# Inject N", "# Facilitation Tips".
- Each inject must have a title, description, objective, and a valid JSON log entry in a ```json``` block under **Log Evidence**.
- JSON logs must be valid, unique, tailored to the technologies (e.g., Fortinet syslog format), and reflect the inject’s event.
- Do not omit any section or inject.
- Do not reference external files or use placeholders like "[Insert log here]".
- Ensure content is realistic and relevant to the basis and TTPs.
"""
        logger.info(f"Sending prompt to Ollama:\n{prompt}")  # Log prompt for debugging
        response = await query_ollama(prompt)
        if response.startswith("Error") or response.startswith("Failed"):
            logger.error(f"Ollama query failed: {response}")
            return f"Error generating document: {response}"

        markdown = response.strip()
        logger.info(f"Raw Markdown:\n{markdown}")  # Log raw Markdown for debugging

        # Initialize JSON structure
        json_data = {
            "day_time": data['day_time'],
            "basis": {
                "id": data['basis_id'],
                "type": data['basis_type']
            },
            "technologies": data['technologies'],
            "num_injects": data['num_injects'],
            "ttps": data['ttps'],
            "narrative": "",
            "injects": [],
            "facilitation_tips": ""
        }

        # Parse Markdown to capture all content
        lines = markdown.split('\n')
        current_section = None
        current_inject = None
        in_log_block = False
        log_lines = []
        narrative_lines = []
        facilitation_lines = []

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue  # Skip empty lines
            logger.debug(f"Parsing line {i+1}: {line}")  # Log each line for tracing

            # Detect section headers
            if line.lower().startswith('# narrative'):
                current_section = 'narrative'
                logger.debug("Entered narrative section")
                continue
            elif line.lower().startswith('# inject'):
                current_section = 'injects'
                if current_inject:
                    # Finalize previous inject
                    current_inject['description'] = '\n'.join(current_inject['description']).strip()
                    current_inject['objective'] = '\n'.join(current_inject['objective']).strip()
                    if not current_inject['log_entry']:
                        current_inject['log_entry'] = {
                            "timestamp": (datetime.datetime.fromisoformat(base_time[:-1]) + 
                                         datetime.timedelta(minutes=5*(len(json_data['injects'])))).isoformat() + "Z",
                            "event": f"Activity for {current_inject['title']}",
                            "source": "unknown",
                            "details": "Generated as no log entry was provided"
                        }
                    logger.debug(f"Finalized inject: {current_inject['title']}")
                current_inject = {
                    "title": line,
                    "description": [],
                    "objective": [],
                    "log_entry": None
                }
                json_data['injects'].append(current_inject)
                logger.debug(f"Started new inject: {line}")
                continue
            elif line.lower().startswith('# facilitation tips'):
                current_section = 'facilitation_tips'
                logger.debug("Entered facilitation tips section")
                continue
            elif line == '```json':
                in_log_block = True
                log_lines = []
                logger.debug("Entered JSON log block")
                continue
            elif line == '```' and in_log_block:
                in_log_block = False
                if current_inject:
                    log_content = '\n'.join(log_lines).strip()
                    try:
                        current_inject['log_entry'] = json.loads(log_content)
                        logger.debug(f"Parsed log entry for {current_inject['title']}: {log_content}")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON log entry for {current_inject['title']}: {e}")
                        current_inject['log_entry'] = {
                            "timestamp": (datetime.datetime.fromisoformat(base_time[:-1]) + 
                                         datetime.timedelta(minutes=5*(len(json_data['injects'])))).isoformat() + "Z",
                            "event": f"Activity for {current_inject['title']}",
                            "source": "unknown",
                            "details": "Generated due to invalid JSON"
                        }
                continue

            # Assign content to sections
            if in_log_block:
                log_lines.append(line)
            elif current_section == 'narrative':
                narrative_lines.append(line)
            elif current_section == 'facilitation_tips':
                facilitation_lines.append(line)
            elif current_section == 'injects' and current_inject:
                if line.lower().startswith('**objective**:'):
                    current_inject['objective'].append(line.replace('**Objective**: ', '', 1).strip())
                    logger.debug(f"Added objective: {line}")
                elif line.lower().startswith('**log evidence**'):
                    continue  # Skip Log Evidence heading
                else:
                    current_inject['description'].append(line)
                    logger.debug(f"Added description line: {line}")

        # Finalize any pending inject
        if current_inject:
            current_inject['description'] = '\n'.join(current_inject['description']).strip()
            current_inject['objective'] = '\n'.join(current_inject['objective']).strip()
            if not current_inject['log_entry']:
                current_inject['log_entry'] = {
                    "timestamp": (datetime.datetime.fromisoformat(base_time[:-1]) + 
                                 datetime.timedelta(minutes=5*(len(json_data['injects'])))).isoformat() + "Z",
                    "event": f"Activity for {current_inject['title']}",
                    "source": "unknown",
                    "details": "Generated as no log entry was provided"
                }
                logger.debug(f"Added fallback log entry for {current_inject['title']}")

        # Assign collected lines to JSON
        json_data['narrative'] = '\n'.join(narrative_lines).strip()
        json_data['facilitation_tips'] = '\n'.join(facilitation_lines).strip()

        # Fallback if sections are empty
        if not json_data['narrative']:
            json_data['narrative'] = f"A threat actor ({data['basis_id']}) targets the {', '.join(data['technologies'])} environment on {data['day_time']}."
            logger.warning("No narrative found; added fallback")
        if not json_data['injects']:
            for i in range(1, data['num_injects'] + 1):
                inject = {
                    "title": f"# Inject {i}: Placeholder Incident",
                    "description": f"Simulated incident {i} affecting {', '.join(data['technologies'])}.",
                    "objective": "Analyze the incident and propose mitigation.",
                    "log_entry": {
                        "timestamp": (datetime.datetime.fromisoformat(base_time[:-1]) + 
                                     datetime.timedelta(minutes=5*i)).isoformat() + "Z",
                        "event": f"Placeholder event for inject {i}",
                        "source": "unknown",
                        "details": "Generated as no inject content was provided"
                    }
                }
                json_data['injects'].append(inject)
            logger.warning(f"No injects found; added {data['num_injects']} placeholder injects")
        if not json_data['facilitation_tips']:
            json_data['facilitation_tips'] = "Encourage team discussion, ensure all participants contribute, and review logs carefully."
            logger.warning("No facilitation tips found; added fallback")

        # Validate and fix JSON blocks in Markdown
        json_blocks = re.findall(r'```json\n(.*?)\n```', markdown, re.DOTALL)
        for i, block in enumerate(json_blocks, 1):
            try:
                json.loads(block)
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON in inject {i}: {e}")
                log_entry = {
                    "timestamp": (datetime.datetime.fromisoformat(base_time[:-1]) + 
                                 datetime.timedelta(minutes=5*i)).isoformat() + "Z",
                    "event": f"Activity for inject {i}",
                    "source": "unknown",
                    "details": "Generated due to invalid JSON"
                }
                markdown = markdown.replace(
                    f'```json\n{block}\n```',
                    f'```json\n{json.dumps(log_entry, indent=2)}\n```'
                )

        logger.info(f"Parsed JSON data:\n{json.dumps(json_data, indent=2)}")  # Log parsed JSON
        return {"markdown": markdown, "json": json_data}
    except Exception as e:
        logger.error(f"Error generating document: {e}")
        return f"Error generating document: {e}"

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
        html += '<p>Please specify the attack basis: a Group ID (e.g., G0027), Software ID (e.g., S0002), Campaign ID (e.g., C0027), or a general term like "ransomware":</p>'
        return html

    elif step == 'basis':
        if not user_input:
            return '<p>Please provide a valid attack basis.</p>'
        mitre_data = fetch_mitre_details(user_input)
        if mitre_data['type'] == 'error':
            return f'<p>Error fetching MITRE details: {mitre_data["details"]}</p>'
        data['basis_type'] = mitre_data['type']
        if mitre_data['type'] != 'generic':
            data['basis_id'] = (mitre_data['details'].get('group_id') or 
                                mitre_data['details'].get('software_id') or 
                                mitre_data['details'].get('campaign_id') or 
                                user_input)
            attack_id = data['basis_id']
            data['ttps'] = []
            if attack_id:
                entities, _ = graph.fetch_linked_entities(attack_id)
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
        session.modified = True

        result = asyncio.run(generate_tabletop_document(data))
        if isinstance(result, str) and (result.startswith("Error") or result.startswith("Failed")):
            logger.error(f"Tabletop generation failed: {result}")
            html = f'<p>{result}</p>'
            html += '<p>Please try again or check the Ollama server configuration.</p>'
        else:
            markdown = result['markdown']
            json_data = result['json']
            session['markdown_content'] = markdown

            # Save JSON to tabletops table
            try:
                conn = connect_to_db()
                cursor = conn.cursor()
                filename = f"tabletop_{data['basis_id']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                cursor.execute(
                    "INSERT INTO tabletops (user_id, json_data, filename) VALUES (%s, %s, %s)",
                    (current_user.id, json.dumps(json_data), filename)
                )
                conn.commit()
                conn.close()
                logger.info(f"Saved tabletop JSON for user {current_user.id} as {filename}")
            except Exception as e:
                logger.error(f"Error saving tabletop JSON: {e}")

            html = '<h2>Tabletop Document Generated</h2>'
            html += '<pre>' + markdown + '</pre>'
            html += '<p><a href="/download" download>Download Markdown</a></p>'
            if current_user.is_authenticated:
                save_conversation(current_user.id, 'bot', html)
        session.pop('tabletop_step', None)
        session['tabletop_data'] = {}
        session.modified = True
        return html

    return '<p>Invalid tabletop state. Start a new exercise with <code>create tabletop</code>.</p>'

@app.route('/download')
@login_required
def download_markdown():
    """Serve the generated Markdown file for download."""
    markdown_content = session.get('markdown_content')
    if not markdown_content:
        return "Error: No Markdown content available for download.", 404

    buffer = io.BytesIO()
    buffer.write(markdown_content.encode('utf-8'))
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name='tabletop_exercise.md',
        mimetype='text/markdown'
    )

def save_conversation(user_id, sender, text, image=None):
    """Save a conversation message to the database."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO conversations (user_id, sender, text, image) VALUES (%s, %s, %s, %s)",
            (user_id, sender, text, image)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error saving conversation: {e}")

def load_conversation(user_id):
    """Load conversation history for a user."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT sender, text, image FROM conversations WHERE user_id = %s ORDER BY created_at",
            (user_id,)
        )
        conversation = cursor.fetchall()
        conn.close()
        return conversation
    except Exception as e:
        logger.error(f"Error loading conversation: {e}")
        return []

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('register.html', error="Username and password are required.")
        
        try:
            conn = connect_to_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                conn.close()
                return render_template('register.html', error="Username already exists.")
            
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return render_template('register.html', error="Registration failed. Try again.")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error="Username and password are required.")
        
        try:
            conn = connect_to_db()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, username, password_hash FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                user_obj = User(user['id'], user['username'])
                login_user(user_obj)
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error="Invalid username or password.")
        except Exception as e:
            logger.error(f"Error logging in: {e}")
            return render_template('login.html', error="Login failed. Try again.")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    """Render the main chat interface and handle user input."""
    conversation = load_conversation(current_user.id)
    
    if request.method == 'POST':
        user_input = request.form.get('user_input', '').strip()
        if not user_input:
            return jsonify({'response': '<p>Please enter a command.</p>'})

        if user_input.lower() == 'clear':
            try:
                conn = connect_to_db()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM conversations WHERE user_id = %s", (current_user.id,))
                conn.commit()
                conn.close()
                session.pop('tabletop_step', None)
                session.pop('tabletop_data', None)
                session['markdown_content'] = None
                session.modified = True
                return jsonify({'response': '<p>Conversation cleared. Start with <code>create tabletop</code>.</p>'})
            except Exception as e:
                logger.error(f"Error clearing conversation: {e}")
                return jsonify({'response': '<p>Error clearing conversation.</p>'})

        save_conversation(current_user.id, 'user', user_input)
        
        if user_input.lower() == 'create tabletop':
            session['tabletop_step'] = 'day_time'
            session['tabletop_data'] = {}
            session.modified = True
            response = '<p>Please specify the day and time for the tabletop exercise (e.g., "Monday morning"):</p>'
        else:
            response = handle_tabletop_input(user_input)

        save_conversation(current_user.id, 'bot', response)
        return jsonify({'response': response})

    return render_template('index.html', conversation=conversation)

@app.route('/send', methods=['POST'])
@login_required
def send_message():
    """Handle AJAX message sending."""
    user_input = request.form['message'].strip().lower()
    if not user_input:
        return jsonify({'response': 'Please enter a message.'})

    # Handle 'run tabletop' command (client-side redirect, no server response needed)
    if user_input == 'run-tabletop':
        return jsonify({'response': 'Opening tabletop exercise in a new tab.'})

    save_conversation(current_user.id, 'user', user_input)

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
        save_conversation(current_user.id, 'bot', response['text'], response['image'])
    else:
        save_conversation(current_user.id, 'bot', response)
    
    return jsonify({'response': response})

@app.route('/run_tabletop')
@app.route('/run_tabletop/<int:tabletop_id>')
@login_required
def run_tabletop(tabletop_id=None):
    """Render the tabletop exercise runtime environment."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, filename, json_data FROM tabletops WHERE user_id = %s ORDER BY created_at DESC",
            (current_user.id,)
        )
        tabletops = cursor.fetchall()
        
        if tabletop_id:
            cursor.execute(
                "SELECT id, filename, json_data FROM tabletops WHERE id = %s AND user_id = %s",
                (tabletop_id, current_user.id)
            )
            tabletop = cursor.fetchone()
            if tabletop:
                tabletop_data = json.loads(tabletop['json_data'])
                tabletop_data['id'] = tabletop['id']
                conn.close()
                return render_template('run_tabletop.html', tabletop=tabletop_data, tabletops=tabletops)
            else:
                conn.close()
                return render_template('run_tabletop.html', tabletops=tabletops, error="Tabletop not found or not authorized.")
        
        conn.close()
        return render_template('run_tabletop.html', tabletops=tabletops)
    except Exception as e:
        logger.error(f"Error loading tabletop: {e}")
        return render_template('run_tabletop.html', error="Failed to load tabletops.")

@app.route('/tabletop_note', methods=['POST'])
@login_required
def save_tabletop_note():
    """Save a note for a completed tabletop exercise."""
    tabletop_id = request.form.get('tabletop_id')
    note = request.form.get('note')
    if not tabletop_id or not note:
        return jsonify({'status': 'error', 'message': 'Tabletop ID and note are required.'})
    
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id FROM tabletops WHERE id = %s AND user_id = %s",
            (tabletop_id, current_user.id)
        )
        tabletop = cursor.fetchone()
        if not tabletop:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Tabletop not found or not authorized.'})
        
        cursor.execute(
            "SELECT id, notes FROM completed_tabletops WHERE tabletop_id = %s AND user_id = %s",
            (tabletop_id, current_user.id)
        )
        completed = cursor.fetchone()
        if completed:
            notes = json.loads(completed['notes']) if completed['notes'] else []
            notes.append({'note': note, 'timestamp': datetime.datetime.utcnow().isoformat()})
            cursor.execute(
                "UPDATE completed_tabletops SET notes = %s WHERE id = %s",
                (json.dumps(notes), completed['id'])
            )
        else:
            notes = [{'note': note, 'timestamp': datetime.datetime.utcnow().isoformat()}]
            cursor.execute(
                "INSERT INTO completed_tabletops (user_id, tabletop_id, notes) VALUES (%s, %s, %s)",
                (current_user.id, tabletop_id, json.dumps(notes))
            )
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error saving note: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to save note.'})

@app.route('/export_notes/<int:tabletop_id>')
@login_required
def export_notes(tabletop_id):
    """Export notes for a completed tabletop as a text file."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT notes FROM completed_tabletops WHERE tabletop_id = %s AND user_id = %s",
            (tabletop_id, current_user.id)
        )
        completed = cursor.fetchone()
        conn.close()
        
        if not completed or not completed['notes']:
            return "No notes available for this tabletop.", 404
        
        notes = json.loads(completed['notes'])
        notes_text = "\n".join([f"[{n['timestamp']}] {n['note']}" for n in notes])
        
        buffer = io.BytesIO()
        buffer.write(notes_text.encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'tabletop_{tabletop_id}_notes.txt',
            mimetype='text/plain'
        )
    except Exception as e:
        logger.error(f"Error exporting notes: {e}")
        return "Failed to export notes.", 500

@app.route('/clear', methods=['POST'])
@login_required
def clear_conversation():
    """Clear the user's conversation history."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM conversations WHERE user_id = %s", (current_user.id,))
        conn.commit()
        conn.close()
        session.pop('tabletop_step', None)
        session.pop('tabletop_data', None)
        session['markdown_content'] = None
        session.modified = True
        return jsonify({'status': 'cleared'})
    except Exception as e:
        logger.error(f"Error clearing conversation: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to clear conversation.'})

if __name__ == '__main__':
    logger.info(f"Tabletop command is {'enabled' if ENABLE_TABLETOP else 'disabled'}")
    if ENABLE_TABLETOP and not OLLAMA_URL:
        logger.warning("OLLAMA_URL not set; tabletop creation will fail.")
    app.run(debug=True, host='0.0.0.0', port=5000)