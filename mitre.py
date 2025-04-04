import mysql.connector
from typing import List, Dict, Optional
import re 

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

def validate_ttp_id(ttp_id: str) -> bool:
    """Validate that the TTP ID matches the format T### or T###.###"""
    pattern = r'^T\d{4}(\.\d{3})?$'
    return bool(re.match(pattern, ttp_id))

def get_technique_details(ttp_id: str) -> Optional[Dict[str, any]]:
    """
    Query the database for a technique's description and related TTPs by TTP ID (T### or T###.###).
    Returns a dictionary with description and related TTPs, or None if invalid or not found.
    """
    # Validate TTP ID format
    if not validate_ttp_id(ttp_id):
        print(f"Invalid TTP ID format: {ttp_id}. Must be T#### or T####.###")
        return None


    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)

    # Step 1: Get the technique details (description and tactics) by TTP ID
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
        print(f"No technique found for TTP ID: {ttp_id}")
        conn.close()
        return None

    # Step 2: Find related TTPs based on shared tactics
    tactics = technique['tactic'].split(',') if technique['tactic'] else []
    related_ttps = []
    
    if tactics:
        # Prepare a query with multiple LIKE conditions for each tactic
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

    # Construct the result
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
    print(result)
    return result

def search_by_ttp_id(ttp_id: str) -> List[Dict[str, str]]:
    """
    Search for techniques by their TTP ID (e.g., T1059, T1055.011).
    Returns a list of dictionaries with attack_id, name, and ttp_id.
    """
    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)  # Return results as dictionaries
    
    # Query external_references for matching external_id, join with techniques
    query = """
        SELECT t.id AS attack_id, t.name, er.external_id AS ttp_id
        FROM techniques t
        JOIN external_references er ON t.id = er.technique_id
        WHERE er.source_name = 'mitre-attack'
        AND er.external_id LIKE %s
    """
    cursor.execute(query, (f"{ttp_id}%",))  # Using LIKE with % for sub-techniques (e.g., T1055.011)
    
    results = cursor.fetchall()
    
    conn.close()
    return results

def search_by_name_or_description(search_term: str) -> List[Dict[str, str]]:
    """
    Search for techniques by keywords in name or description.
    Returns a list of dictionaries with attack_id, name, and ttp_id.
    """
    conn = connect_to_db()
    cursor = conn.cursor(dictionary=True)  # Return results as dictionaries
    
    # Query techniques and join with external_references for TTP ID
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

    """
    Search for groups by ATT&CK ID (e.g., G0001) or name.
    Returns a list of dictionaries with group details and related techniques.
    """
    try:
        conn = connect_to_db()
        cursor = conn.cursor(dictionary=True)

        # Check if query matches group ID format
        is_group_id = validate_group_id(query)
        
        if is_group_id:
            # Search by exact group ID
            query_sql = """
                SELECT g.id AS attack_id, g.name, g.description, er.external_id AS group_id
                FROM groups g
                JOIN external_references er ON g.id = er.technique_id
                WHERE er.source_name = 'mitre-attack'
                AND er.external_id = %s
            """
            cursor.execute(query_sql, (query,))
        else:
            # Search by name (partial match)
            query_sql = """
                SELECT g.id AS attack_id, g.name, g.description, er.external_id AS group_id
                FROM groups g
                LEFT JOIN external_references er ON g.id = er.technique_id AND er.source_name = 'mitre-attack'
                WHERE g.name LIKE %s
            """
            cursor.execute(query_sql, (f"%{query}%",))

        groups = cursor.fetchall()

        if not groups:
            print(f"No groups found for query: {query}")
            conn.close()
            return []

        # For each group, fetch related techniques
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
        print(f"Database error: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def search_software(query: str) -> Optional[List[Dict[str, any]]]:
    """Search for software by ATT&CK ID (e.g., S####) or name."""
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
        
        if not results:
            print(f"No software found for query: {query}")
            return []
        return results

    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def search_campaigns(query: str) -> Optional[List[Dict[str, any]]]:

    """Search for campaigns by ATT&CK ID (e.g., C####) or name."""
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
                LEFT JOIN campaign_external_references cer ON c.id = cer.campaign_id AND cer.source_name = 'mitre-attack'
                WHERE c.name LIKE %s
            """
            cursor.execute(query_sql, (f"%{query}%",))

        results = cursor.fetchall()
        conn.close()
        
        if not results:
            print(f"No campaigns found for query: {query}")
            return []
        return results

    except mysql.connector.Error as e:
        print(f"Database error: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def validate_id(attck_id: str, prefix: str) -> bool:
    """Validate that the ID matches the format S#### or C####"""
    pattern = rf'^{prefix}\d{{4}}$'
    return bool(re.match(pattern, attck_id))

