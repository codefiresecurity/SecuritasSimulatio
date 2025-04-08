import networkx as nx
import matplotlib.pyplot as plt
from io import BytesIO
from mitre import fetch_linked_entities  # Assuming this fetches MITRE data

def generate_graph(query: str):
    """Generate a graph of linked MITRE ATT&CK entities for the given query."""
    # Normalize query to uppercase to handle g0018 vs G0018
    query = query.upper()

    # Fetch linked entities (e.g., TTPs, groups, software, campaigns)
    entities, relationships = fetch_linked_entities(query)
    if not entities or not relationships:
        return None

    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes (entities)
    for entity_id, entity in entities.items():
        G.add_node(entity_id, label=entity.get('name', entity_id), type=entity['type'])

    # Add edges (relationships)
    for rel in relationships:
        G.add_edge(rel['source'], rel['target'], label=rel.get('relationship_type', ''))

    # Use spring layout with adjusted parameters for better spacing
    # Increase k (distance between nodes) and iterations for busy graphs
    pos = nx.spring_layout(G, k=1.5, iterations=100, scale=2.0)

    # Set up the plot
    plt.figure(figsize=(12, 8))  # Larger figure size for readability
    node_colors = {
        'technique': '#FF9999',
        'group': '#99FF99',
        'software': '#9999FF',
        'campaign': '#FFFF99'
    }

    # Draw nodes with colors based on type
    for node, data in G.nodes(data=True):
        nx.draw_networkx_nodes(G, pos, nodelist=[node], node_color=node_colors.get(data['type'], '#CCCCCC'), node_size=800)

    # Draw edges
    nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=20)

    # Draw labels
    node_labels = {node: data['label'] for node, data in G.nodes(data=True)}
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=10, font_weight='bold')

    # Draw edge labels (if any)
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)

    # Save to BytesIO buffer
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
    buffer.seek(0)
    plt.close()
    return buffer

def fetch_linked_entities(query: str):
    """Placeholder for fetching linked entities from MITRE data."""
    # This should be your actual implementation from mitre.py
    # Returning dummy data for demonstration
    entities = {
        query: {'name': f'{query} Name', 'type': 'technique'},
        'G0007': {'name': 'APT28', 'type': 'group'},
        'S0001': {'name': 'Trojan', 'type': 'software'}
    }
    relationships = [
        {'source': query, 'target': 'G0007', 'relationship_type': 'used-by'},
        {'source': query, 'target': 'S0001', 'relationship_type': 'uses'}
    ]
    return entities, relationships