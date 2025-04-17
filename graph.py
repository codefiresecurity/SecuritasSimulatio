import mysql.connector
import networkx as nx
import matplotlib.pyplot as plt
import discord
from discord import app_commands
from typing import Dict, List, Optional
import io
import re
import matplotlib.patches as mpatches  # Added for legend
import os
from dotenv import load_dotenv
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB = os.getenv("DB")
def connect_to_db(
    host: str = DB_HOST,
    user: str = DB_USER,
    password: str = DB_PASS,
    database: str = DB
) -> mysql.connector.connection.MySQLConnection:
    """Establish a connection to the MySQL database."""
    return mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database
    )

def validate_id(query: str, prefix: str) -> bool:
    """Validate ATT&CK ID format (e.g., T####, S####, C####, G####)."""
    pattern = rf'^{prefix}\d{{4}}(\.\d{{3}})?$'
    return bool(re.match(pattern, query))

def fetch_linked_entities(query: str) -> tuple[Dict[str, any], List[tuple]]:
    logger.info(f"Fetching entities for query: {query}")
    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)

    is_uuid = re.match(r'^[a-z]+--[0-9a-f-]+$', query, re.I)
    focal_entity = None
    entity_type = None
    table = None
    ref_table = None
    id_field = None

    if is_uuid:
        for _type, _table, _ref_table, _id_field in [
            ('group', 'groups', 'group_external_references', 'group_id'),
            ('technique', 'techniques', 'external_references', 'technique_id'),
            ('software', 'software', 'software_external_references', 'software_id'),
            ('campaign', 'campaigns', 'campaign_external_references', 'campaign_id')
        ]:
            cursor.execute(f"""
                SELECT t.id AS attack_id, t.name, er.external_id AS attck_id
                FROM {_table} t
                LEFT JOIN {_ref_table} er ON t.id = er.{_id_field} AND er.source_name = 'mitre-attack'
                WHERE t.id = %s
            """, (query,))
            focal_entity = cursor.fetchone()
            if focal_entity:
                logger.info(f"Found entity in {_table} for UUID: {query}")
                entity_type = _type
                table = _table
                ref_table = _ref_table
                id_field = _id_field
                break
            else:
                logger.debug(f"No entity in {_table} for UUID: {query}")
    else:
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
            entity_type = 'group'
            table = 'groups'
            ref_table = 'group_external_references'
            id_field = 'group_id'

        if entity_type in ['technique', 'group', 'software', 'campaign'] and validate_id(query, entity_type[0].upper()):
            query_sql = f"""
                SELECT t.id AS attack_id, t.name, er.external_id AS attck_id
                FROM {table} t
                JOIN {ref_table} er ON t.id = er.{id_field}
                WHERE er.source_name = 'mitre-attack'
                AND er.external_id = %s
            """
            cursor.execute(query_sql, (query,))
        else:
            query_sql = """
                SELECT g.id AS attack_id, g.name, er.external_id AS attck_id
                FROM groups g
                LEFT JOIN group_external_references er ON g.id = er.group_id AND er.source_name = 'mitre-attack'
                WHERE g.name LIKE %s
            """
            cursor.execute(query_sql, (f"%{query}%",))

        focal_entity = cursor.fetchone()
        if focal_entity:
            logger.info(f"Found entity for ATT&CK ID/name: {query}")

    if not focal_entity:
        logger.warning(f"No focal entity found for query: {query}")
        conn.close()
        return {}, []

    entities = {focal_entity['attack_id']: {
        'name': focal_entity['name'],
        'attck_id': focal_entity['attck_id'] or focal_entity['attack_id'],
        'type': entity_type
    }}

    relationships = []
    cursor.execute("""
        SELECT source_id, target_id, relationship_type
        FROM relationships
        WHERE source_id = %s OR target_id = %s
    """, (focal_entity['attack_id'], focal_entity['attack_id']))
    for rel in cursor.fetchall():
        relationships.append((rel['source_id'], rel['target_id'], rel['relationship_type']))

    related_ids = set()
    for src, tgt, _ in relationships:
        related_ids.add(src)
        related_ids.add(tgt)
    related_ids.discard(focal_entity['attack_id'])

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
    logger.info(f"Found entities for {query}: {entities}")
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
    
    # Dynamic figure sizing based on node count
    node_count = len(G.nodes)
    # Base size with minimums, scaled by node count
    width = max(12, min(24, 12 + (node_count // 10)))
    height = max(8, min(18, 8 + (node_count // 15)))
    plt.figure(figsize=(width, height))
    
    # Define node colors based on type
    color_map = {
        'technique': 'lightblue',
        'group': 'lightgreen',
        'software': 'lightcoral',
        'campaign': 'lightyellow'
    }
    node_colors = [color_map[G.nodes[node]['type']] for node in G.nodes]
    
    # Improve layout with better spacing parameters
    # For large graphs, increase k (node repulsion) to spread nodes more
    k_value = 0.3 + (0.05 * min(node_count // 5, 10))  # Scale with node count but cap increase
    pos = nx.spring_layout(G, k=k_value, iterations=50, seed=42)
    
    # Calculate appropriate node size (smaller when more nodes)
    node_size = max(1200, 3000 - (node_count * 50))
    font_size = max(6, 10 - (node_count // 20))
    
    # Draw nodes and edges
    nx.draw(G, pos, with_labels=True, labels=nx.get_node_attributes(G, 'label'),
            node_color=node_colors, node_size=node_size, font_size=font_size, 
            font_weight='bold', alpha=0.9, edge_color='gray')
    
    # Add edge labels with improved visibility
    edge_labels = nx.get_edge_attributes(G, 'label')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, 
                               font_size=max(5, font_size-2),
                               font_color='navy',
                               bbox={'boxstyle': 'round,pad=0.2', 'fc': 'white', 'alpha': 0.7})

    # Add legend
    legend_patches = [
        mpatches.Patch(color='lightblue', label='Techniques'),
        mpatches.Patch(color='lightgreen', label='Groups'),
        mpatches.Patch(color='lightcoral', label='Software'),
        mpatches.Patch(color='lightyellow', label='Campaigns')
    ]
    plt.legend(handles=legend_patches, loc='upper right', title='Entity Types')
    
    # Check if graph is too crowded (heuristic)
    is_crowded = node_count > 30 or (node_count > 15 and len(relationships) > 30)
    if is_crowded:
        plt.figtext(0.5, 0.01, 
                  f"Large dataset detected ({node_count} nodes). Consider using more specific queries.",
                  ha='center', fontsize=10, bbox={"facecolor":"orange", "alpha":0.2, "pad":5})

    # Save to BytesIO with tight layout
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=100)
    img_buffer.seek(0)
    plt.close()
    return img_buffer