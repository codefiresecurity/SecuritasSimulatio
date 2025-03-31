import os
import discord

from dotenv import load_dotenv
load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")

intents = discord.Intents.all()

client = discord.Client(intents=intents)

@client.event
async def on_ready():
    print(f'{client.user} has connected to Discord!')


@client.event
async def on_message(message):
    if message.content == "ping":
        msg = "pong"
        await message.channel.send(msg)

    if message.content == '/help':
        msg = "**/help** - Displays this message."
        await message.channel.send(msg)

    if message.content == '/attack':
        msg = ""


client.run(TOKEN)