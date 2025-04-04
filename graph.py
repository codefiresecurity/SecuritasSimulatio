import mysql.connector
import networkx as nx
import matplotlib.pyplot as plt
import discord
from discord import app_commands
from typing import Dict, List, Optional
import io
import re
import matplotlib.patches as mpatches  # Added for legend

# Database connection
def connect_to_db(
    host: str = "10.5.10.101",
    user: str = "rwessels",
    password: str = "Division113!",
    database: str = "mitre"
) -> mysql.connector.connection.MySQLConnection:
    """Establish a connection to the MySQL database."""
    return mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database
    )

# Validation functions
def validate_id(query: str, prefix: str) -> bool:
    """Validate ATT&CK ID format (e.g., T####, S####, C####, G####)."""
    pattern = rf'^{prefix}\d{{4}}(\.\d{{3}})?$'
    return bool(re.match(pattern, query))

# Fetch entity and relationships
def fetch_linked_entities(query: str) -> Optional[tuple[Dict[str, str], List[tuple]]]:
    """Fetch the focal entity and its linked entities from the database."""
    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)

    # Determine entity type based on query format
    entity_type = None
    if validate_id(query, 'T'):
        entity_type = 'technique'
        table = 'techniques'
        ref_table = 'external_references'
        id_field = 'technique_id'
    elif validate_id(query, 'G'):
        entity_type = 'group'
        table = 'groups'
        ref_table = 'group_external_references'
        id_field = 'group_id'
    elif validate_id(query, 'S'):
        entity_type = 'software'
        table = 'software'
        ref_table = 'software_external_references'
        id_field = 'software_id'
    elif validate_id(query, 'C'):
        entity_type = 'campaign'
        table = 'campaigns'
        ref_table = 'campaign_external_references'
        id_field = 'campaign_id'
    else:
        # Assume group name if not an ID
        entity_type = 'group'
        table = 'groups'
        ref_table = 'group_external_references'
        id_field = 'group_id'

    # Fetch focal entity
    if entity_type in ['technique', 'group', 'software', 'campaign'] and validate_id(query, entity_type[0].upper()):
        query_sql = f"""
            SELECT t.id AS attack_id, t.name, er.external_id AS attck_id
            FROM {table} t
            JOIN {ref_table} er ON t.id = er.{id_field}
            WHERE er.source_name = 'mitre-attack'
            AND er.external_id = %s
        """
        cursor.execute(query_sql, (query,))
    else:  # Search by group name
        query_sql = """
            SELECT g.id AS attack_id, g.name, er.external_id AS attck_id
            FROM groups g
            LEFT JOIN group_external_references er ON g.id = er.group_id AND er.source_name = 'mitre-attack'
            WHERE g.name LIKE %s
        """
        cursor.execute(query_sql, (f"%{query}%",))

    focal_entity = cursor.fetchone()
    if not focal_entity:
        conn.close()
        return None

    entities = {focal_entity['attack_id']: {
        'name': focal_entity['name'],
        'attck_id': focal_entity['attck_id'] or focal_entity['attack_id'],
        'type': entity_type
    }}

    # Fetch all relationships involving the focal entity
    relationships = []
    cursor.execute("""
        SELECT source_id, target_id, relationship_type
        FROM relationships
        WHERE source_id = %s OR target_id = %s
    """, (focal_entity['attack_id'], focal_entity['attack_id']))
    for rel in cursor.fetchall():
        relationships.append((rel['source_id'], rel['target_id'], rel['relationship_type']))

    # Fetch all related entities
    related_ids = set()
    for src, tgt, _ in relationships:
        related_ids.add(src)
        related_ids.add(tgt)
    related_ids.discard(focal_entity['attack_id'])  # Remove focal entity

    for table, entity_type in [('techniques', 'technique'), ('groups', 'group'), ('software', 'software'), ('campaigns', 'campaign')]:
        if related_ids:
            ref_table = ('external_references' if table == 'techniques' else 
                         'group_external_references' if table == 'groups' else 
                         'software_external_references' if table == 'software' else 
                         'campaign_external_references')
            id_field = ('technique_id' if table == 'techniques' else 
                       'group_id' if table == 'groups' else 
                       'software_id' if table == 'software' else 
                       'campaign_id')
            query_related = f"""
                SELECT t.id AS attack_id, t.name, er.external_id AS attck_id
                FROM {table} t
                LEFT JOIN {ref_table} er ON t.id = er.{id_field} AND er.source_name = 'mitre-attack'
                WHERE t.id IN ({','.join(['%s'] * len(related_ids))})
            """
            cursor.execute(query_related, tuple(related_ids))
            for row in cursor.fetchall():
                entities[row['attack_id']] = {
                    'name': row['name'],
                    'attck_id': row['attck_id'] or row['attack_id'],
                    'type': entity_type
                }

    conn.close()
    return entities, relationships

def generate_graph(query: str) -> Optional[io.BytesIO]:
    """Generate a graph image from the query and return it as a BytesIO object with a legend."""
    data = fetch_linked_entities(query)
    if not data:
        return None

    entities, relationships = data
    G = nx.DiGraph()

    # Add nodes
    for entity_id, info in entities.items():
        G.add_node(entity_id, label=f"{info['attck_id']}\n{info['name']}", type=info['type'])

    # Add edges
    for src, tgt, rel_type in relationships:
        if src in entities and tgt in entities:  # Ensure both nodes exist
            G.add_edge(src, tgt, label=rel_type)

    # Define node colors based on type
    color_map = {
        'technique': 'lightblue',
        'group': 'lightgreen',
        'software': 'lightcoral',
        'campaign': 'lightyellow'
    }
    node_colors = [color_map[G.nodes[node]['type']] for node in G.nodes]

    # Draw the graph
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, labels=nx.get_node_attributes(G, 'label'),
            node_color=node_colors, node_size=2000, font_size=8, font_weight='bold')
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)

    # Add legend
    legend_patches = [
        mpatches.Patch(color='lightblue', label='Techniques'),
        mpatches.Patch(color='lightgreen', label='Groups'),
        mpatches.Patch(color='lightcoral', label='Software'),
        mpatches.Patch(color='lightyellow', label='Campaigns')
    ]
    plt.legend(handles=legend_patches, loc='upper right', title='Entity Types')

    # Save to BytesIO
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', bbox_inches='tight')
    img_buffer.seek(0)
    plt.close()
    return img_buffer