import requests
import json
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
OLLAMA_URL = os.getenv("OLLAMA_URL")

def test_ollama():
    # Replace with your Ollama server URL
    ollama_url = OLLAMA_URL
    
    # Basic test prompt
    payload = {
        "model": "mistral",  # Replace with your model name if different
        "prompt": "Hello, can you hear me?",
        "stream": False
    }
    
    print("Sending request to Ollama...")
    
    try:
        response = requests.post(ollama_url, json=payload)
        if response.status_code == 200:
            result = response.json()
            print("Ollama response status: Success!")
            print("Response content:")
            print(result.get('response', 'No response field found in the result'))
            return True
        else:
            print(f"Error: Ollama returned status {response.status_code}")
            print("Response:", response.text)
            return False
    except Exception as e:
        print(f"Error connecting to Ollama: {str(e)}")
        return False

if __name__ == "__main__":
    test_ollama()