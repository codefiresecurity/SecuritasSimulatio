import yaml
import requests
import logging
from collections import defaultdict

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Output file
OUTPUT_FILE = "data-sources.yaml"

# URL for ATT&CK Enterprise STIX data
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Generic data source definitions with platforms and layers
GENERIC_DATA_SOURCES = {
    "Authentication Logs": {
        "data_quality": {"score": 2},
        "platforms": ["Windows", "Linux", "Cloud"],
        "collection_layers": ["Host", "Cloud"]
    },
    "Command Execution Logs": {
        "data_quality": {"score": 2},
        "platforms": ["Windows", "Linux"],
        "collection_layers": ["Host"]
    },
    "Endpoint Detection": {
        "data_quality": {"score": 3},
        "platforms": ["Windows", "Linux", "macOS"],
        "collection_layers": ["Host"]
    },
    "File Monitoring": {
        "data_quality": {"score": 2},
        "platforms": ["Windows", "Linux", "macOS"],
        "collection_layers": ["Host"]
    },
    "Firewall": {
        "data_quality": {"score": 3},
        "platforms": ["Network"],
        "collection_layers": ["Network"]
    },
    "Network Traffic": {
        "data_quality": {"score": 3},
        "platforms": ["Windows", "Linux", "Network"],
        "collection_layers": ["Network"]
    },
    "Process Monitoring": {
        "data_quality": {"score": 2},
        "platforms": ["Windows", "Linux", "macOS"],
        "collection_layers": ["Host"]
    },
    "System Logs": {
        "data_quality": {"score": 2},
        "platforms": ["Windows", "Linux", "macOS"],
        "collection_layers": ["Host"]
    },
    "DNS Logs": {
        "data_quality": {"score": 2},
        "platforms": ["Network"],
        "collection_layers": ["Network"]
    },
    "Cloud Audit Logs": {
        "data_quality": {"score": 2},
        "platforms": ["Cloud"],
        "collection_layers": ["Cloud"]
    }
}

# Mapping ATT&CK data source names to our generic names
ATTACK_TO_GENERIC = {
    "Authentication": "Authentication Logs",
    "Command": "Command Execution Logs",
    "Command Execution": "Command Execution Logs",
    "Process": "Process Monitoring",
    "Process monitoring": "Process Monitoring",
    "File": "File Monitoring",
    "Network Traffic": "Network Traffic",
    "Network traffic": "Network Traffic",
    "Firewall": "Firewall",
    "System": "System Logs",
    "Windows event logs": "System Logs",
    "DNS": "DNS Logs",
    "Cloud": "Cloud Audit Logs",
    "Endpoint": "Endpoint Detection"
}

def fetch_attack_data():
    """Fetch ATT&CK Enterprise STIX data and extract technique-to-data-source mappings."""
    logger.info("Fetching ATT&CK STIX data...")
    response = requests.get(ATTACK_STIX_URL)
    response.raise_for_status()
    attack_data = response.json()

    # Map data sources to TTPs
    mappings = defaultdict(set)
    for obj in attack_data["objects"]:
        if obj["type"] == "attack-pattern" and not obj.get("revoked", False):
            ttp_id = next(ref["external_id"] for ref in obj["external_references"] if ref["source_name"] == "mitre-attack")
            data_sources = obj.get("x_mitre_data_sources", [])
            for ds in data_sources:
                # Normalize ATT&CK data source to our generic name
                generic_ds = next((ATTACK_TO_GENERIC[ds_key] for ds_key in ATTACK_TO_GENERIC if ds_key in ds), "Endpoint Detection")  # Fallback
                mappings[generic_ds].add(ttp_id)

    return mappings

def generate_yaml():
    """Generate a comprehensive data-sources.yaml file covering all TTPs."""
    # Fetch ATT&CK mappings
    attack_mappings = fetch_attack_data()

    # Build the data_sources list
    data_sources = []
    for ds_name, base_config in GENERIC_DATA_SOURCES.items():
        config = base_config.copy()
        config["name"] = ds_name
        config["applicable_to"] = sorted(list(attack_mappings.get(ds_name, set())))  # Sort for consistency
        if config["applicable_to"]:  # Only include if it has TTPs
            data_sources.append(config)

    # Write to YAML
    data = {"data_sources": data_sources}
    with open(OUTPUT_FILE, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    logger.info(f"Generated comprehensive {OUTPUT_FILE} with {len(data_sources)} data sources covering {sum(len(ds['applicable_to']) for ds in data_sources)} TTP mappings.")

def main():
    generate_yaml()

if __name__ == "__main__":
    main()