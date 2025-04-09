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
GUILD_ID = os.getenv("GUILD_ID")  # Optional: test server ID
OLLAMA_URL = os.getenv("OLLAMA_URL")

# Set up Discord client with intents
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

logger.info("Script started: Defining functions")

# Efficient string splitting
def split_message(text: str, max_length: int = 1500) -> List[str]:
    """Split text into chunks of max_length, preserving words."""
    return textwrap.wrap(text, width=max_length, break_long_words=False, replace_whitespace=False)

# Unified response sender
async def send_response(interaction: discord.Interaction, message: str, is_initial: bool = False):
    """Send a response, splitting if necessary, respecting interaction state."""
    chunks = split_message(message)
    if is_initial and not interaction.response.is_done():
        if len(chunks) == 1:
            await interaction.response.send_message(chunks[0])
        else:
            await interaction.response.send_message(chunks[0])
            for chunk in chunks[1:]:
                await interaction.followup.send(chunk)
    else:
        for chunk in chunks:
            await interaction.followup.send(chunk)

# Command handlers
async def handle_ttp(interaction: discord.Interaction, method: str, query: str):
    method = method.lower()
    if method not in ['id', 'search', 'detail']:
        await send_response(interaction, "Invalid method. Use `id`, `search`, or `detail`.", is_initial=True)
        return
    if not query:
        await send_response(interaction, "Please provide a query.", is_initial=True)
        return
    if method == 'id':
        result = mitre.search_by_ttp_id(query)
    elif method == 'search':
        result = mitre.search_by_name_or_description(query)
    else:
        result = mitre.get_technique_details(query)
    if not result:
        await send_response(interaction, f"No technique found for: {query.upper()}", is_initial=True)
        return
    if method == 'detail':
        msg = f"TTP ID: {result['ttp_id']}\nName: {result['name']}\nDescription: {result['description']}\n---------\n"
    else:
        msg = '\n'.join(f"{res['ttp_id']} - {res['name']}" for res in result)
    await send_response(interaction, msg, is_initial=True)

async def handle_group(interaction: discord.Interaction, query: str):
    results = mitre.search_groups(query)
    if not results:
        await send_response(interaction, f"No groups found for query: {query}", is_initial=True)
        return
    msg = ''.join(f"Group ID: {r['group_id']}\nName: {r['name']}\nAttack ID: {r['attack_id']}\nDescription: {r['description']}\n" for r in results)
    await send_response(interaction, msg, is_initial=True)

async def handle_software(interaction: discord.Interaction, query: str):
    results = mitre.search_software(query)
    if not results:
        await send_response(interaction, f"No software found for query: {query}", is_initial=True)
        return
    msg = ''.join(f"Software ID: {r['software_id']}\nName: {r['name']}\nAttack ID: {r['attack_id']}\nDescription: {r['description']}\n" for r in results)
    await send_response(interaction, msg, is_initial=True)

async def handle_campaign(interaction: discord.Interaction, query: str):
    results = mitre.search_campaigns(query)
    if not results:
        await send_response(interaction, f"No campaigns found for query: {query}", is_initial=True)
        return
    msg = ''.join(f"Campaign ID: {r['campaign_id']}\nName: {r['name']}\nAttack ID: {r['attack_id']}\nDescription: {r['description']}\n" for r in results)
    await send_response(interaction, msg, is_initial=True)

async def handle_graph(interaction: discord.Interaction, query: str):
    query = query.upper()
    await send_response(interaction, "Generating graph, please wait...", is_initial=True)
    img_buffer = graph.generate_graph(query)
    if img_buffer:
        file = discord.File(img_buffer, filename=f"{query}_chart.png")
        await interaction.followup.send(f"Chart for {query}:", file=file)
    else:
        await interaction.followup.send(f"No linked items found for {query}")

async def recommend_log_sources(interaction: discord.Interaction, query: str):
    """Recommend log sources in a clean, Discord-friendly format."""
    query = query.upper()
    await send_response(interaction, f"Analyzing log source coverage for **{query}**...", is_initial=True)

    # Fetch linked TTPs using existing graph logic
    entities, _ = graph.fetch_linked_entities(query)
    ttps = [e['attck_id'] for e in entities.values() if e['type'] == 'technique']

    if not ttps:
        await interaction.followup.send(f"No techniques found for **{query}**.")
        return

    # Get recommendations from mitre.py
    recommendations = mitre.recommend_log_sources(ttps)

    if "error" in recommendations:
        await interaction.followup.send(recommendations["error"])
        return

    # Build the formatted output
    msg_lines = [f"**Log Source Recommendations for {query}**"]
    msg_lines.append(f"Queried TTPs: {recommendations['total_ttps']} | Covered: {recommendations['covered_ttps']} ({recommendations['coverage_percentage']:.1f}%)")
    msg_lines.append(f"**This is an estimated coverage based on available data sources. Validate with your own data!**")
    msg_lines.append("```")

    # Log Sources Section
    if recommendations["log_sources"]:
        msg_lines.append("🔍 Log Sources:")
        for source_name, details in recommendations["log_sources"].items():
            ttps_str = ", ".join(details["covered_ttps"][:5])  # Limit to 5 TTPs for brevity
            if len(details["covered_ttps"]) > 5:
                ttps_str += f" (+{len(details['covered_ttps']) - 5} more)"
            msg_lines.append(
                f"• {source_name} (Q: {details['quality']}/3, P: {details['platforms']})\n"
                f"  Covered: {ttps_str}"
            )

    # Blind Spots Section
    if recommendations["blind_spots"]:
        blind_spots_str = ", ".join(recommendations["blind_spots"][:5])  # Limit to 5 for brevity
        if len(recommendations["blind_spots"]) > 5:
            blind_spots_str += f" (+{len(recommendations['blind_spots']) - 5} more)"
        msg_lines.append("⚠️ Blind Spots:")
        msg_lines.append(f"• {blind_spots_str}")

    msg_lines.append("```")
    msg = "\n".join(msg_lines)
    
    await send_response(interaction, msg)

# Tabletop Command Logic (simplified for testing)
async def collect_tabletop_data(user: discord.User, dm_channel: discord.DMChannel) -> Dict:
    """Collect tabletop exercise data from the user via DM."""
    data = {}
    def check(m):
        return m.author == user and m.channel == dm_channel
    await dm_channel.send("Please specify the day of the week and time of day (e.g., 'Monday morning'):")
    msg = await client.wait_for('message', check=check, timeout=300.0)
    data['day_time'] = msg.content.strip()
    return data

async def generate_tabletop_document(data: Dict) -> str:
    """Generate tabletop document by querying Ollama and return as Markdown."""
    return "## Test Document\nGenerated for: " + data['day_time']

# Discord Events
@client.event
async def on_ready():
    logger.info(f'{client.user} has connected to Discord!')
    try:
        if GUILD_ID:
            guild = discord.Object(id=int(GUILD_ID))
            await tree.sync(guild=guild)
            logger.info(f"Slash commands synced to guild {GUILD_ID}")
            commands = tree.get_commands(guild=guild)
        else:
            await tree.sync()
            logger.info("Slash commands synced globally")
            commands = tree.get_commands()
        logger.info(f"Registered commands: {[cmd.name for cmd in commands]}")
    except Exception as e:
        logger.error(f"Failed to sync commands: {e}")

# Slash Commands
logger.info("Defining slash commands")

@tree.command(name="attack", description="Query MITRE ATT&CK data or get log recommendations")
@app_commands.describe(
    query_type="Type of query (ttp, group, software, campaign, graph, recommend)",
    method="For TTP: id, search, or detail (optional)",
    query="The ID or name to search for"
)
async def attack(interaction: discord.Interaction, query_type: str, method: str = None, query: str = None):
    logger.info(f"Command invoked: attack with query_type={query_type}, method={method}, query={query}")
    query_type = query_type.lower()
    handlers = {
        'ttp': handle_ttp,
        'group': handle_group,
        'software': handle_software,
        'campaign': handle_campaign,
        'graph': handle_graph,
        'recommend': recommend_log_sources
    }
    if query_type not in handlers:
        await send_response(interaction, "Invalid query type. Use `ttp`, `group`, `software`, `campaign`, `graph`, or `recommend`.", is_initial=True)
        return
    if query_type == 'ttp':
        if not method:
            await send_response(interaction, "For TTP, specify a method: `id`, `search`, or `detail`.", is_initial=True)
            return
        if not query:
            await send_response(interaction, "Please provide a query for TTP.", is_initial=True)
            return
        await handle_ttp(interaction, method, query)
    else:
        if not query:
            await send_response(interaction, "Please provide a query.", is_initial=True)
            return
        await handlers[query_type](interaction, query)

@tree.command(name="help", description="Show available commands")
async def help_command(interaction: discord.Interaction):
    logger.info("Command registered: help")
    msg = (
        "**/attack <query_type> [method] <query>** - Query MITRE ATT&CK data or get recommendations\n"
        "- `query_type`: `ttp`, `group`, `software`, `campaign`, `graph`, `recommend`\n"
        "- `method` (for `ttp` only): `id`, `search`, `detail`\n"
        "- `query`: ID (e.g., T1059) or name\n"
        "**/help** - Display this message\n"
        "**/create-tabletop** - Start a DM to create a tabletop exercise document"
    )
    await send_response(interaction, msg, is_initial=True)

@tree.command(name="create-tabletop", description="Test command for tabletop creation")
async def create_tabletop(interaction: discord.Interaction):
    logger.info("Command registered: create-tabletop")
    await send_response(interaction, "Test: Tabletop command works!", is_initial=True)

# Legacy on_message handler
@client.event
async def on_message(message):
    if message.author == client.user:
        return
    if message.content == "ping":
        await message.channel.send("pong")

logger.info("Script fully loaded: Starting bot")

# Run the bot
client.run(TOKEN)