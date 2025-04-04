import os
import discord
from discord import app_commands
from dotenv import load_dotenv
import mitre
import graph
import textwrap
from typing import List, Dict
import logging
import aiohttp
import io

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
OLLAMA_URL = os.getenv("OLLAMA_URL")

# Set up Discord client with intents
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# Efficient string splitting
def split_message(text: str, max_length: int = 1500) -> List[str]:
    """Split text into chunks of max_length, preserving words."""
    return textwrap.wrap(text, width=max_length, break_long_words=False, replace_whitespace=False)

# Unified response sender
async def send_response(interaction: discord.Interaction, message: str):
    """Send a response, splitting if necessary."""
    chunks = split_message(message)
    if len(chunks) == 1:
        await interaction.response.send_message(chunks[0])
    else:
        await interaction.response.send_message(chunks[0])
        for chunk in chunks[1:]:
            await interaction.followup.send(chunk)

# Command handlers
async def handle_ttp(interaction: discord.Interaction, method: str, query: str):
    method = method.lower()
    if method not in ['id', 'search', 'detail']:
        await interaction.response.send_message("Invalid method. Use `id`, `search`, or `detail`.")
        return
    if not query:
        await interaction.response.send_message("Please provide a query.")
        return
    if method == 'id':
        result = mitre.search_by_ttp_id(query)
    elif method == 'search':
        result = mitre.search_by_name_or_description(query)
    else:
        result = mitre.get_technique_details(query)
    if not result:
        await interaction.response.send_message(f"No technique found for: {query.upper()}")
        return
    if method == 'detail':
        msg = f"TTP ID: {result['ttp_id']}\nName: {result['name']}\nDescription: {result['description']}\n---------\n"
    else:
        msg = '\n'.join(f"{res['ttp_id']} - {res['name']}" for res in result)
    await send_response(interaction, msg)

async def handle_group(interaction: discord.Interaction, query: str):
    results = mitre.search_groups(query)
    if not results:
        await interaction.response.send_message(f"No groups found for query: {query}")
        return
    msg = ''.join(f"Group ID: {r['group_id']}\nName: {r['name']}\nAttack ID: {r['attack_id']}\nDescription: {r['description']}\n" for r in results)
    await send_response(interaction, msg)

async def handle_software(interaction: discord.Interaction, query: str):
    results = mitre.search_software(query)
    if not results:
        await interaction.response.send_message(f"No software found for query: {query}")
        return
    msg = ''.join(f"Software ID: {r['software_id']}\nName: {r['name']}\nAttack ID: {r['attack_id']}\nDescription: {r['description']}\n" for r in results)
    await send_response(interaction, msg)

async def handle_campaign(interaction: discord.Interaction, query: str):
    results = mitre.search_campaigns(query)
    if not results:
        await interaction.response.send_message(f"No campaigns found for query: {query}")
        return
    msg = ''.join(f"Campaign ID: {r['campaign_id']}\nName: {r['name']}\nAttack ID: {r['attack_id']}\nDescription: {r['description']}\n" for r in results)
    await send_response(interaction, msg)

async def handle_graph(interaction: discord.Interaction, query: str):
    await interaction.response.send_message("Generating graph, please wait...", ephemeral=True)
    img_buffer = graph.generate_graph(query)
    if img_buffer:
        file = discord.File(img_buffer, filename=f"{query}_chart.png")
        await interaction.followup.send(f"Chart for {query}:", file=file)
    else:
        await interaction.followup.send(f"No linked items found for {query}")

# Tabletop Command Logic
async def collect_tabletop_data(user: discord.User, dm_channel: discord.DMChannel) -> Dict:
    """Collect tabletop exercise data from the user via DM."""
    data = {}
    
    def check(m):
        return m.author == user and m.channel == dm_channel

    await dm_channel.send("Please specify the day of the week and time of day (e.g., 'Monday morning', 'Friday night'):")
    msg = await client.wait_for('message', check=check, timeout=300.0)
    data['day_time'] = msg.content.strip()

    await dm_channel.send("List the technologies in use (e.g., 'Fortinet, Microsoft AD, Cisco'):")
    msg = await client.wait_for('message', check=check, timeout=300.0)
    data['technologies'] = [tech.strip() for tech in msg.content.split(',')]

    await dm_channel.send("How many injects do you want? (Enter a number):")
    while True:
        msg = await client.wait_for('message', check=check, timeout=300.0)
        try:
            data['num_injects'] = int(msg.content.strip())
            if data['num_injects'] > 0:
                break
            await dm_channel.send("Please enter a positive number.")
        except ValueError:
            await dm_channel.send("Invalid input. Please enter a number.")

    await dm_channel.send(
        "Specify the attack basis:\n"
        "- For TTP chain, list TTPs separated by commas (e.g., 'T1059, T1071')\n"
        "- For software, group, or campaign, enter its ID (e.g., 'S0001', 'G0007', 'C0001')\n"
        "What would you like to use?"
    )
    msg = await client.wait_for('message', check=check, timeout=300.0)
    basis_input = msg.content.strip()

    if ',' in basis_input:
        data['basis_type'] = 'ttp_chain'
        data['ttps'] = [ttp.strip() for ttp in basis_input.split(',')]
    else:
        entities, _ = graph.fetch_linked_entities(basis_input) or ({}, [])
        if not entities:
            await dm_channel.send(f"No data found for {basis_input}. Defaulting to empty TTP list.")
            data['ttps'] = []
        else:
            focal_entity = next(iter(entities.values()))
            data['basis_type'] = focal_entity['type']
            data['basis_id'] = basis_input
            data['ttps'] = [
                entity['attck_id'] for entity_id, entity in entities.items()
                if entity['type'] == 'technique' and entity_id != focal_entity.get('attack_id')
            ]

    return data

async def generate_tabletop_document(data: Dict) -> str:
    """Generate tabletop document by querying Ollama and return as Markdown."""
    prompt = (
        "Generate a tabletop facilitation document in Markdown format for a cybersecurity exercise with the following details:\n"
        f"- Day and Time: {data['day_time']}\n"
        f"- Technologies in Use: {', '.join(data['technologies'])}\n"
        f"- Number of Injects: {data['num_injects']}\n"
        f"- Attack Basis: {data['basis_type']} ({data.get('basis_id', 'TTP Chain')})\n"
        f"- TTPs Involved: {', '.join(data['ttps']) if data['ttps'] else 'None'}\n\n"
        "Include:\n"
        "1. A short narrative of the event (200-300 words) under a `## Narrative` heading.\n"
        "2. Each inject with a corresponding sample log file from a relevant system (e.g., Fortinet, Microsoft AD) under `## Injects` with subheadings `### Inject X`.\n"
        "3. Facilitation tips under a `## Facilitation Tips` heading.\n"
        "Use Markdown syntax (e.g., `##`, `###`, `-` for lists, ``` for code blocks)."
    )

    async with aiohttp.ClientSession() as session:
        payload = {
            "model": "mistral",
            "prompt": prompt,
            "stream": False
        }
        try:
            async with session.post(OLLAMA_URL, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get('response', 'Error: No response from Ollama')
                else:
                    return f"Error: Ollama returned status {response.status}"
        except Exception as e:
            return f"Error connecting to Ollama: {str(e)}"

# Define slash commands
@tree.command(name="attack", description="Query MITRE ATT&CK data")
@app_commands.describe(
    query_type="Type of query (ttp, group, software, campaign, graph)",
    method="For TTP: id, search, or detail (optional)",
    query="The ID or name to search for"
)
async def attack(interaction: discord.Interaction, query_type: str, method: str = None, query: str = None):
    logger.info("Command executed: attack")
    query_type = query_type.lower()
    handlers = {
        'ttp': handle_ttp,
        'group': handle_group,
        'software': handle_software,
        'campaign': handle_campaign,
        'graph': handle_graph
    }
    if query_type not in handlers:
        await interaction.response.send_message("Invalid query type. Use `ttp`, `group`, `software`, `campaign`, or `graph`.")
        return
    if query_type == 'ttp':
        if not method:
            await interaction.response.send_message("For TTP, specify a method: `id`, `search`, or `detail`.")
            return
        if not query:
            await interaction.response.send_message("Please provide a query for TTP.")
            return
        await handle_ttp(interaction, method, query)
    else:
        if not query:
            await interaction.response.send_message("Please provide a query.")
            return
        await handlers[query_type](interaction, query)

@tree.command(name="help", description="Show available commands")
async def help_command(interaction: discord.Interaction):
    logger.info("Command executed: help")
    msg = (
        "**/attack <query_type> [method] <query>** - Query MITRE ATT&CK data\n"
        "- `query_type`: `ttp`, `group`, `software`, `campaign`, `graph`\n"
        "- `method` (for `ttp` only): `id`, `search`, `detail`\n"
        "- `query`: ID (e.g., T1059) or name\n"
        "**/help** - Display this message\n"
        "**/create-tabletop** - Start a DM to create a tabletop exercise document"
    )
    await interaction.response.send_message(msg)

@tree.command(name="create-tabletop", description="Start a DM to create a tabletop exercise document")
async def create_tabletop(interaction: discord.Interaction):
    logger.info("Command executed: create-tabletop")
    """Initiate a DM to gather data and generate a tabletop document with Markdown download."""
    user = interaction.user
    dm_channel = None
    try:
        dm_channel = await user.create_dm()
        await interaction.response.send_message("I've started a DM with you to gather details for the tabletop exercise!", ephemeral=True)
        await dm_channel.send("Let's create a tabletop facilitation document. I'll ask you a few questions.")

        # Collect data
        data = await collect_tabletop_data(user, dm_channel)

        # Generate document
        await dm_channel.send("Generating your tabletop document, please wait...")
        document = await generate_tabletop_document(data)

        # Send document as text
        chunks = split_message(document, max_length=2000)
        for chunk in chunks:
            await dm_channel.send(chunk)

        # Send document as Markdown file
        md_buffer = io.BytesIO(document.encode('utf-8'))
        md_file = discord.File(md_buffer, filename="tabletop_facilitation_guide.md")
        await dm_channel.send("Here's your facilitation guide as a downloadable Markdown file:", file=md_file)

        await dm_channel.send("Document generated! Let me know if you need adjustments.")
    except discord.errors.Forbidden:
        await interaction.response.send_message("I can't send you a DM. Please enable DMs from server members.", ephemeral=True)
    except Exception as e:
        logger.error(f"Create-tabletop command error: {e}")
        if dm_channel:
            await dm_channel.send(f"An error occurred: {str(e)}. Please try again or contact support.")

# Discord Events
@client.event
async def on_ready():
    logger.info(f'{client.user} has connected to Discord!')
    try:
        # Log all currently registered commands before syncing
        pre_commands = tree.get_commands()
        logger.info(f"Pre-sync registered commands: {[cmd.name for cmd in pre_commands]}")
        
        try:
            await tree.sync()
            commands = tree.get_commands()
        except Exception as e:
            logger.error(f"Failed to sync commands: {e}", exc_info=True)
        logger.info(f"Post-sync registered commands: {[cmd.name for cmd in commands]}")
    except Exception as e:
        logger.error(f"Failed to sync commands: {e}")

# Legacy on_message handler
@client.event
async def on_message(message):
    if message.author == client.user:
        return
    if message.content == "ping":
        await message.channel.send("pong")

# Run the bot
client.run(TOKEN)