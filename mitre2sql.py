import json
from datetime import datetime

def generate_mitre_sql(json_file_path, sql_file_path="mitre_full.sql"):
    """Generate an SQL file for the mitre database from enterprise-attack.json."""
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Open SQL file for writing
    with open(sql_file_path, 'w', encoding='utf-8') as sql_file:
        # Helper function to escape SQL values
        def escape_sql(text):
            if text is None or text == '':
                return 'NULL'
            return f"'{str(text).replace('\'', '')}'"  # Remove single quotes to avoid SQL errors

        # --- Table Creation ---
        # Techniques
        sql_file.write("-- Create techniques table\n")
        sql_file.write("""
            CREATE TABLE techniques (
                id VARCHAR(100) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                created VARCHAR(50),
                modified VARCHAR(50),
                attack_version VARCHAR(10),
                tactic TEXT,
                platforms TEXT,
                detection TEXT,
                mitigation TEXT
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_techniques_id ON techniques (id);\n\n")

        # Groups
        sql_file.write("-- Create groups table\n")
        sql_file.write("""
            CREATE TABLE groups (
                id VARCHAR(100) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                created VARCHAR(50),
                modified VARCHAR(50)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_groups_id ON groups (id);\n\n")

        # Software
        sql_file.write("-- Create software table\n")
        sql_file.write("""
            CREATE TABLE software (
                id VARCHAR(100) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                created VARCHAR(50),
                modified VARCHAR(50),
                software_type VARCHAR(50)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_software_id ON software (id);\n\n")

        # Campaigns
        sql_file.write("-- Create campaigns table\n")
        sql_file.write("""
            CREATE TABLE campaigns (
                id VARCHAR(100) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                created VARCHAR(50),
                modified VARCHAR(50)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_campaigns_id ON campaigns (id);\n\n")

        # External References
        sql_file.write("-- Create external_references table (for techniques)\n")
        sql_file.write("""
            CREATE TABLE external_references (
                technique_id VARCHAR(100),
                source_name VARCHAR(100),
                external_id VARCHAR(50),
                url TEXT,
                FOREIGN KEY (technique_id) REFERENCES techniques (id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_extref_technique_id ON external_references (technique_id);\n")
        sql_file.write("CREATE INDEX idx_extref_external_id ON external_references (external_id);\n\n")

        sql_file.write("-- Create group_external_references table\n")
        sql_file.write("""
            CREATE TABLE group_external_references (
                group_id VARCHAR(100),
                source_name VARCHAR(100),
                external_id VARCHAR(50),
                url TEXT,
                FOREIGN KEY (group_id) REFERENCES groups (id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_group_extref_group_id ON group_external_references (group_id);\n")
        sql_file.write("CREATE INDEX idx_group_extref_external_id ON group_external_references (external_id);\n\n")

        sql_file.write("-- Create software_external_references table\n")
        sql_file.write("""
            CREATE TABLE software_external_references (
                software_id VARCHAR(100),
                source_name VARCHAR(100),
                external_id VARCHAR(50),
                url TEXT,
                FOREIGN KEY (software_id) REFERENCES software (id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_software_extref_software_id ON software_external_references (software_id);\n")
        sql_file.write("CREATE INDEX idx_software_extref_external_id ON software_external_references (external_id);\n\n")

        sql_file.write("-- Create campaign_external_references table\n")
        sql_file.write("""
            CREATE TABLE campaign_external_references (
                campaign_id VARCHAR(100),
                source_name VARCHAR(100),
                external_id VARCHAR(50),
                url TEXT,
                FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_campaign_extref_campaign_id ON campaign_external_references (campaign_id);\n")
        sql_file.write("CREATE INDEX idx_campaign_extref_external_id ON campaign_external_references (external_id);\n\n")

        # Relationship Tables
        sql_file.write("-- Create group_technique_relationships\n")
        sql_file.write("""
            CREATE TABLE group_technique_relationships (
                group_id VARCHAR(100),
                technique_id VARCHAR(100),
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (technique_id) REFERENCES techniques (id),
                PRIMARY KEY (group_id, technique_id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_group_tech_group_id ON group_technique_relationships (group_id);\n")
        sql_file.write("CREATE INDEX idx_group_tech_technique_id ON group_technique_relationships (technique_id);\n\n")

        sql_file.write("-- Create software_technique_relationships\n")
        sql_file.write("""
            CREATE TABLE software_technique_relationships (
                software_id VARCHAR(100),
                technique_id VARCHAR(100),
                FOREIGN KEY (software_id) REFERENCES software (id),
                FOREIGN KEY (technique_id) REFERENCES techniques (id),
                PRIMARY KEY (software_id, technique_id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_software_tech_software_id ON software_technique_relationships (software_id);\n")
        sql_file.write("CREATE INDEX idx_software_tech_technique_id ON software_technique_relationships (technique_id);\n\n")

        sql_file.write("-- Create campaign_technique_relationships\n")
        sql_file.write("""
            CREATE TABLE campaign_technique_relationships (
                campaign_id VARCHAR(100),
                technique_id VARCHAR(100),
                FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                FOREIGN KEY (technique_id) REFERENCES techniques (id),
                PRIMARY KEY (campaign_id, technique_id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_campaign_tech_campaign_id ON campaign_technique_relationships (campaign_id);\n")
        sql_file.write("CREATE INDEX idx_campaign_tech_technique_id ON campaign_technique_relationships (technique_id);\n\n")

        sql_file.write("-- Create group_campaign_relationships\n")
        sql_file.write("""
            CREATE TABLE group_campaign_relationships (
                group_id VARCHAR(100),
                campaign_id VARCHAR(100),
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                PRIMARY KEY (group_id, campaign_id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_group_camp_group_id ON group_campaign_relationships (group_id);\n")
        sql_file.write("CREATE INDEX idx_group_camp_campaign_id ON group_campaign_relationships (campaign_id);\n\n")

        sql_file.write("-- Create generic relationships table\n")
        sql_file.write("""
            CREATE TABLE relationships (
                source_id VARCHAR(100),
                target_id VARCHAR(100),
                relationship_type VARCHAR(50),
                PRIMARY KEY (source_id, target_id)
            );\n\n
        """)
        sql_file.write("CREATE INDEX idx_rel_source_id ON relationships (source_id);\n")
        sql_file.write("CREATE INDEX idx_rel_target_id ON relationships (target_id);\n\n")

        # --- Data Insertion ---
        technique_count = 0
        group_count = 0
        software_count = 0
        campaign_count = 0
        ext_ref_count = 0
        group_ext_ref_count = 0
        software_ext_ref_count = 0
        campaign_ext_ref_count = 0
        group_tech_count = 0
        soft_tech_count = 0
        camp_tech_count = 0
        group_camp_count = 0
        generic_rel_count = 0

        sql_file.write("-- Insert data\n")
        for item in data.get('objects', []):
            item_type = item.get('type')

            # Techniques (attack-pattern)
            if item_type == 'attack-pattern':
                sql_file.write("-- Insert technique\n")
                technique_id = item.get('id')
                name = escape_sql(item.get('name'))
                description = escape_sql(item.get('description', ''))
                created = escape_sql(item.get('created'))
                modified = escape_sql(item.get('modified'))
                attack_version = escape_sql(item.get('spec_version'))
                tactics = escape_sql(','.join(phase.get('phase_name', '') for phase in item.get('kill_chain_phases', []) if isinstance(phase, dict)))
                platforms = escape_sql(','.join(item.get('x_mitre_platforms', [])))
                detection = escape_sql(item.get('x_mitre_detection', ''))
                mitigation = escape_sql('')

                sql_file.write(f"""
                    INSERT INTO techniques 
                    (id, name, description, created, modified, attack_version, tactic, platforms, detection, mitigation)
                    VALUES (
                        '{technique_id}', {name}, {description}, {created}, {modified}, 
                        {attack_version}, {tactics}, {platforms}, {detection}, {mitigation}
                    );\n
                """)
                technique_count += 1

                for ref in item.get('external_references', []):
                    sql_file.write(f"""
                        INSERT INTO external_references 
                        (technique_id, source_name, external_id, url)
                        VALUES (
                            '{technique_id}', {escape_sql(ref.get('source_name'))}, 
                            {escape_sql(ref.get('external_id'))}, {escape_sql(ref.get('url'))}
                        );\n
                    """)
                    ext_ref_count += 1

            # Groups (intrusion-set)
            elif item_type == 'intrusion-set':
                sql_file.write("-- Insert group\n")
                group_id = item.get('id')
                name = escape_sql(item.get('name'))
                description = escape_sql(item.get('description', ''))
                created = escape_sql(item.get('created'))
                modified = escape_sql(item.get('modified'))

                sql_file.write(f"""
                    INSERT INTO groups 
                    (id, name, description, created, modified)
                    VALUES (
                        '{group_id}', {name}, {description}, {created}, {modified}
                    );\n
                """)
                group_count += 1

                for ref in item.get('external_references', []):
                    sql_file.write(f"""
                        INSERT INTO group_external_references 
                        (group_id, source_name, external_id, url)
                        VALUES (
                            '{group_id}', {escape_sql(ref.get('source_name'))}, 
                            {escape_sql(ref.get('external_id'))}, {escape_sql(ref.get('url'))}
                        );\n
                    """)
                    group_ext_ref_count += 1

            # Software (malware or tool)
            elif item_type in ['malware', 'tool']:
                sql_file.write("-- Insert software\n")
                software_id = item.get('id')
                name = escape_sql(item.get('name'))
                description = escape_sql(item.get('description', ''))
                created = escape_sql(item.get('created'))
                modified = escape_sql(item.get('modified'))
                software_type = escape_sql(item_type)

                sql_file.write(f"""
                    INSERT INTO software 
                    (id, name, description, created, modified, software_type)
                    VALUES (
                        '{software_id}', {name}, {description}, {created}, {modified}, {software_type}
                    );\n
                """)
                software_count += 1

                for ref in item.get('external_references', []):
                    sql_file.write(f"""
                        INSERT INTO software_external_references 
                        (software_id, source_name, external_id, url)
                        VALUES (
                            '{software_id}', {escape_sql(ref.get('source_name'))}, 
                            {escape_sql(ref.get('external_id'))}, {escape_sql(ref.get('url'))}
                        );\n
                    """)
                    software_ext_ref_count += 1

            # Campaigns (campaign)
            elif item_type == 'campaign':
                sql_file.write("-- Insert campaign\n")
                campaign_id = item.get('id')
                name = escape_sql(item.get('name'))
                description = escape_sql(item.get('description', ''))
                created = escape_sql(item.get('created'))
                modified = escape_sql(item.get('modified'))

                sql_file.write(f"""
                    INSERT INTO campaigns 
                    (id, name, description, created, modified)
                    VALUES (
                        '{campaign_id}', {name}, {description}, {created}, {modified}
                    );\n
                """)
                campaign_count += 1

                for ref in item.get('external_references', []):
                    sql_file.write(f"""
                        INSERT INTO campaign_external_references 
                        (campaign_id, source_name, external_id, url)
                        VALUES (
                            '{campaign_id}', {escape_sql(ref.get('source_name'))}, 
                            {escape_sql(ref.get('external_id'))}, {escape_sql(ref.get('url'))}
                        );\n
                    """)
                    campaign_ext_ref_count += 1

            # Relationships
            elif item_type == 'relationship' and item.get('relationship_type'):
                source_ref = item.get('source_ref')
                target_ref = item.get('target_ref')
                rel_type = item.get('relationship_type')

                sql_file.write(f"""
                    INSERT IGNORE INTO relationships 
                    (source_id, target_id, relationship_type)
                    VALUES (
                        '{source_ref}', '{target_ref}', '{rel_type}'
                    );\n
                """)
                generic_rel_count += 1

                if rel_type == 'uses':
                    if source_ref.startswith('intrusion-set--') and target_ref.startswith('attack-pattern--'):
                        sql_file.write(f"""
                            INSERT IGNORE INTO group_technique_relationships 
                            (group_id, technique_id)
                            VALUES (
                                '{source_ref}', '{target_ref}'
                            );\n
                        """)
                        group_tech_count += 1
                    elif source_ref.startswith('malware--') or source_ref.startswith('tool--'):
                        if target_ref.startswith('attack-pattern--'):
                            sql_file.write(f"""
                                INSERT IGNORE INTO software_technique_relationships 
                                (software_id, technique_id)
                                VALUES (
                                    '{source_ref}', '{target_ref}'
                                );\n
                            """)
                            soft_tech_count += 1
                    elif source_ref.startswith('campaign--') and target_ref.startswith('attack-pattern--'):
                        sql_file.write(f"""
                            INSERT IGNORE INTO campaign_technique_relationships 
                            (campaign_id, technique_id)
                            VALUES (
                                '{source_ref}', '{target_ref}'
                            );\n
                        """)
                        camp_tech_count += 1
                elif rel_type == 'attributed-to':
                    if source_ref.startswith('campaign--') and target_ref.startswith('intrusion-set--'):
                        sql_file.write(f"""
                            INSERT IGNORE INTO group_campaign_relationships 
                            (group_id, campaign_id)
                            VALUES (
                                '{target_ref}', '{source_ref}'
                            );\n
                        """)
                        group_camp_count += 1

        # --- Summary ---
        sql_file.write(f"\n-- Summary of Inserted Data:\n")
        sql_file.write(f"-- Techniques: {technique_count}\n")
        sql_file.write(f"-- Groups: {group_count}\n")
        sql_file.write(f"-- Software: {software_count}\n")
        sql_file.write(f"-- Campaigns: {campaign_count}\n")
        sql_file.write(f"-- External References (Techniques): {ext_ref_count}\n")
        sql_file.write(f"-- Group External References: {group_ext_ref_count}\n")
        sql_file.write(f"-- Software External References: {software_ext_ref_count}\n")
        sql_file.write(f"-- Campaign External References: {campaign_ext_ref_count}\n")
        sql_file.write(f"-- Group-Technique Relationships: {group_tech_count}\n")
        sql_file.write(f"-- Software-Technique Relationships: {soft_tech_count}\n")
        sql_file.write(f"-- Campaign-Technique Relationships: {camp_tech_count}\n")
        sql_file.write(f"-- Group-Campaign Relationships: {group_camp_count}\n")
        sql_file.write(f"-- Generic Relationships: {generic_rel_count}\n")
        sql_file.write(f"-- Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

def main():
    json_file_path = 'enterprise-attack.json'
    sql_file_path = 'mitre_full.sql'
    
    try:
        generate_mitre_sql(json_file_path, sql_file_path)
        print(f"Successfully generated {sql_file_path}")
    except FileNotFoundError:
        print(f"Error: Could not find {json_file_path}. Please download it from https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()