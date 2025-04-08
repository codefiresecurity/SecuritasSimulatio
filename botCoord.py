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
OLLAMA_URL = "http://your-ollama-ip:11434/api/generate"  # Replace with your Ollama server IP

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
async def send_response(interaction: discord.Interaction, message: str):
    """Send a response, splitting if necessary."""
    chunks = split_message(message)
    if len(chunks) == 1:
        await interaction.response.send_message(chunks[0])
    else:
        await interaction.response.send_message(chunks[0])
        for chunk in chunks[1:]:
            await interaction.followup.send(chunk)

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

try:
    @tree.command(name="create-tabletop", description="Test command for tabletop creation")
    async def create_tabletop(interaction: discord.Interaction):
        logger.info("Command registered and executed: create-tabletop")
        await interaction.response.send_message("Test: Tabletop command works!", ephemeral=True)
except Exception as e:
    logger.error(f"Error defining create-tabletop: {e}")

@tree.command(name="attack", description="Query MITRE ATT&CK data")
@app_commands.describe(
    query_type="Type of query (ttp, group, software, campaign, graph)",
    method="For TTP: id, search, or detail (optional)",
    query="The ID or name to search for"
)
async def attack(interaction: discord.Interaction, query_type: str, method: str = None, query: str = None):
    logger.info("Command registered: attack")
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
    logger.info("Command registered: help")
    msg = (
        "**/attack <query_type> [method] <query>** - Query MITRE ATT&CK data\n"
        "- `query_type`: `ttp`, `group`, `software`, `campaign`, `graph`\n"
        "- `method` (for `ttp` only): `id`, `search`, `detail`\n"
        "- `query`: ID (e.g., T1059) or name\n"
        "**/help** - Display this message\n"
        "**/create-tabletop** - Start a DM to create a tabletop exercise document"
    )
    await interaction.response.send_message(msg)

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
    query = query.upper()  # Normalize query to uppercase
    await interaction.response.send_message("Generating graph, please wait...", ephemeral=True)
    img_buffer = graph.generate_graph(query)
    if img_buffer:
        file = discord.File(img_buffer, filename=f"{query}_chart.png")
        await interaction.followup.send(f"Chart for {query}:", file=file)
    else:
        await interaction.followup.send(f"No linked items found for {query}")

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