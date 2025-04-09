import mysql.connector
from typing import List, Dict, Optional
import re 
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
    try:
        return mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
    except mysql.connector.Error as e:
        logger.error(f"Database connection error: {e}")
        raise

def validate_ttp_id(ttp_id: str) -> bool:
    """Validate that the TTP ID matches the format T### or T###.###"""
    pattern = r'^T\d{4}(\.\d{3})?$'
    return bool(re.match(pattern, ttp_id))

def get_technique_details(ttp_id: str) -> Optional[Dict[str, any]]:
    """Query the database for a technique's description and related TTPs by TTP ID."""
    if not validate_ttp_id(ttp_id):
        logger.warning(f"Invalid TTP ID format: {ttp_id}. Must be T#### or T####.###")
        return None

    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)

    query_technique = """
        SELECT t.id AS attack_id, t.name, t.description, t.tactic, er.external_id AS ttp_id
        FROM techniques t
        JOIN external_references er ON t.id = er.technique_id
        WHERE er.source_name = 'mitre-attack'
        AND er.external_id = %s
    """
    cursor.execute(query_technique, (ttp_id,))
    technique = cursor.fetchone()

    if not technique:
        logger.info(f"No technique found for TTP ID: {ttp_id}")
        conn.close()
        return None

    tactics = technique['tactic'].split(',') if technique['tactic'] else []
    related_ttps = []
    
    if tactics:
        placeholders = ' OR '.join(['t.tactic LIKE %s' for _ in tactics])
        query_related = f"""
            SELECT DISTINCT t.id AS attack_id, t.name, er.external_id AS ttp_id
            FROM techniques t
            JOIN external_references er ON t.id = er.technique_id
            WHERE er.source_name = 'mitre-attack'
            AND ({placeholders})
            AND er.external_id != %s
        """
        params = [f"%{tactic}%" for tactic in tactics] + [ttp_id]
        cursor.execute(query_related, params)
        related_ttps = cursor.fetchall()

    conn.close()

    result = {
        "ttp_id": technique["ttp_id"],
        "name": technique["name"],
        "attack_id": technique["attack_id"],
        "description": technique["description"],
        "related_ttps": [
            {"ttp_id": r["ttp_id"], "name": r["name"], "attack_id": r["attack_id"]}
            for r in related_ttps
        ]
    }
    return result

def search_by_ttp_id(ttp_id: str) -> List[Dict[str, str]]:
    """Search for techniques by their TTP ID."""
    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT t.id AS attack_id, t.name, er.external_id AS ttp_id
        FROM techniques t
        JOIN external_references er ON t.id = er.technique_id
        WHERE er.source_name = 'mitre-attack'
        AND er.external_id LIKE %s
    """
    cursor.execute(query, (f"{ttp_id}%",))
    results = cursor.fetchall()
    
    conn.close()
    return results

def search_by_name_or_description(search_term: str) -> List[Dict[str, str]]:
    """Search for techniques by keywords in name or description."""
    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT t.id AS attack_id, t.name, er.external_id AS ttp_id
        FROM techniques t
        LEFT JOIN external_references er ON t.id = er.technique_id AND er.source_name = 'mitre-attack'
        WHERE (t.name LIKE %s OR t.description LIKE %s)
    """
    search_pattern = f"%{search_term}%"
    cursor.execute(query, (search_pattern, search_pattern))
    results = cursor.fetchall()
    
    conn.close()
    return results
    
def validate_group_id(group_id: str) -> bool:
    """Validate that the group ID matches the format G####"""
    pattern = r'^G\d{4}$'
    return bool(re.match(pattern, group_id))

def search_groups(query: str) -> Optional[List[Dict[str, any]]]:
    """Search for groups by ATT&CK ID or name."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)
        is_group_id = validate_group_id(query)
        
        if is_group_id:
            query_sql = """
                SELECT g.id AS attack_id, g.name, g.description, er.external_id AS group_id
                FROM groups g
                JOIN external_references er ON g.id = er.technique_id
                WHERE er.source_name = 'mitre-attack'
                AND er.external_id = %s
            """
            cursor.execute(query_sql, (query,))
        else:
            query_sql = """
                SELECT g.id AS attack_id, g.name, g.description, er.external_id AS group_id
                FROM groups g
                LEFT JOIN external_references er ON g.id = er.technique_id AND er.source_name = 'mitre-attack'
                WHERE g.name LIKE %s
            """
            cursor.execute(query_sql, (f"%{query}%",))

        groups = cursor.fetchall()
        if not groups:
            logger.info(f"No groups found for query: {query}")
            conn.close()
            return []

        results = []
        for group in groups:
            cursor.execute("""
                SELECT t.id AS technique_attack_id, t.name AS technique_name, er.external_id AS ttp_id
                FROM group_technique_relationships gtr
                JOIN techniques t ON gtr.technique_id = t.id
                LEFT JOIN external_references er ON t.id = er.technique_id AND er.source_name = 'mitre-attack'
                WHERE gtr.group_id = %s
            """, (group['attack_id'],))
            related_techniques = cursor.fetchall()

            results.append({
                "group_id": group["group_id"],
                "name": group["name"],
                "attack_id": group["attack_id"],
                "description": group["description"],
                "related_techniques": related_techniques
            })

        conn.close()
        return results

    except mysql.connector.Error as e:
        logger.error(f"Database error: {e}")
        return None

def validate_id(attck_id: str, prefix: str) -> bool:
    """Validate that the ID matches the format S#### or C####"""
    pattern = rf'^{prefix}\d{{4}}$'
    return bool(re.match(pattern, attck_id))

def search_software(query: str) -> Optional[List[Dict[str, any]]]:
    """Search for software by ATT&CK ID or name."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)
        is_software_id = validate_id(query, 'S')
        
        if is_software_id:
            query_sql = """
                SELECT s.id AS attack_id, s.name, s.description, s.software_type, ser.external_id AS software_id
                FROM software s
                JOIN software_external_references ser ON s.id = ser.software_id
                WHERE ser.source_name = 'mitre-attack'
                AND ser.external_id = %s
            """
            cursor.execute(query_sql, (query,))
        else:
            query_sql = """
                SELECT s.id AS attack_id, s.name, s.description, s.software_type, ser.external_id AS software_id
                FROM software s
                LEFT JOIN software_external_references ser ON s.id = ser.software_id AND ser.source_name = 'mitre-attack'
                WHERE s.name LIKE %s
            """
            cursor.execute(query_sql, (f"%{query}%",))

        results = cursor.fetchall()
        conn.close()
        return results or []

    except mysql.connector.Error as e:
        logger.error(f"Database error: {e}")
        return None

def search_campaigns(query: str) -> Optional[List[Dict[str, any]]]:
    """Search for campaigns by ATT&CK ID or name."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)
        is_campaign_id = validate_id(query, 'C')
        
        if is_campaign_id:
            query_sql = """
                SELECT c.id AS attack_id, c.name, c.description, cer.external_id AS campaign_id
                FROM campaigns c
                JOIN campaign_external_references cer ON c.id = cer.campaign_id
                WHERE cer.source_name = 'mitre-attack'
                AND cer.external_id = %s
            """
            cursor.execute(query_sql, (query,))
        else:
            query_sql = """
                SELECT c.id AS attack_id, c.name, c.description, cer.external_id AS campaign_id
                FROM campaigns c
                LEFT JOIN campaign_external_references cer ON c.id = cer.campaign_id AND er.source_name = 'mitre-attack'
                WHERE c.name LIKE %s
            """
            cursor.execute(query_sql, (f"%{query}%",))

        results = cursor.fetchall()
        conn.close()
        return results or []

    except mysql.connector.Error as e:
        logger.error(f"Database error: {e}")
        return None

def recommend_log_sources(ttps: List[str]) -> Dict[str, any]:
    """Recommend log sources for a list of TTPs, with coverage and blind spots."""
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)

        # Track log sources and their covered TTPs
        log_sources = {}
        covered_ttps = set()

        for ttp in ttps:
            cursor.execute("""
                SELECT name, quality, platforms, applicable_to
                FROM dettect_data_sources
                WHERE FIND_IN_SET(%s, applicable_to) > 0
            """, (ttp,))
            sources = cursor.fetchall()
            
            if sources:
                covered_ttps.add(ttp)
                for source in sources:
                    source_name = source['name']
                    if source_name not in log_sources:
                        log_sources[source_name] = {
                            "quality": source['quality'],
                            "platforms": source['platforms'],
                            "covered_ttps": set()
                        }
                    log_sources[source_name]["covered_ttps"].add(ttp)

        conn.close()

        # Calculate blind spots (TTPs with no log sources)
        blind_spots = [ttp for ttp in ttps if ttp not in covered_ttps]

        # Calculate coverage percentage
        total_ttps = len(ttps)
        covered_count = len(covered_ttps)
        coverage_percentage = (covered_count / total_ttps * 100) if total_ttps > 0 else 0

        # Convert sets to lists for serialization
        for source in log_sources.values():
            source["covered_ttps"] = sorted(list(source["covered_ttps"]))

        return {
            "log_sources": log_sources,
            "blind_spots": blind_spots,
            "coverage_percentage": coverage_percentage,
            "total_ttps": total_ttps,
            "covered_ttps": covered_count
        }
    except mysql.connector.Error as e:
        logger.error(f"Database error in recommend_log_sources: {e}")
        return {"error": f"Error retrieving log source recommendations: {str(e)}"}