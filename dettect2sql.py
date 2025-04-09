import yaml
import os
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Output SQL file
SQL_FILE = "dettect_import.sql"

def escape_sql_value(value):
    """Escape SQL values (e.g., strings with quotes) or return NULL."""
    if value is None:
        return "NULL"
    if isinstance(value, int):
        return str(value)
    return f"'{str(value).replace('\'', '\\\'')}'"

def generate_create_table():
    """Generate SQL for creating the DeTTECT data sources table."""
    sql = [
        "-- DeTTECT Data Sources Table",
        "CREATE TABLE IF NOT EXISTS dettect_data_sources (",
        "    id INT AUTO_INCREMENT PRIMARY KEY,",
        "    name VARCHAR(255) NOT NULL UNIQUE,",
        "    quality INT,",
        "    platforms VARCHAR(255),",
        "    collection_layers VARCHAR(255),",
        "    applicable_to TEXT  -- Comma-separated technique IDs (e.g., T1059,T1071)",
        ");",
        ""
    ]
    return "\n".join(sql)

def generate_data_sources_inserts(yaml_file):
    """Generate SQL INSERT statements for data sources from YAML."""
    with open(yaml_file, 'r') as f:
        data = yaml.safe_load(f)

    sql = ["-- Inserting DeTTECT Data Sources"]
    for ds in data.get('data_sources', []):
        name = ds.get('name')
        quality = ds.get('data_quality', {}).get('score')
        platforms = ','.join(ds.get('platforms', [])) if ds.get('platforms') else None
        collection_layers = ','.join(ds.get('collection_layers', [])) if ds.get('collection_layers') else None
        applicable_to = ','.join(ds.get('applicable_to', [])) if ds.get('applicable_to') else None

        values = [
            escape_sql_value(name),
            escape_sql_value(quality),
            escape_sql_value(platforms),
            escape_sql_value(collection_layers),
            escape_sql_value(applicable_to)
        ]
        sql.append(
            f"INSERT INTO dettect_data_sources (name, quality, platforms, collection_layers, applicable_to) "
            f"VALUES ({', '.join(values)}) "
            f"ON DUPLICATE KEY UPDATE "
            f"quality = {escape_sql_value(quality)}, "
            f"platforms = {escape_sql_value(platforms)}, "
            f"collection_layers = {escape_sql_value(collection_layers)}, "
            f"applicable_to = {escape_sql_value(applicable_to)};"
        )
    sql.append("")
    return "\n".join(sql)

def main():
    """Main function to generate the SQL file."""
    # Path to DeTTECT data sources YAML file
    data_sources_file = "data-sources.yaml"

    # Check if file exists
    if not os.path.exists(data_sources_file):
        logger.error(f"{data_sources_file} not found. Please provide a valid DeTTECT data-sources.yaml file.")
        return

    # Generate SQL content
    sql_content = [
        f"-- Generated DeTTECT Import SQL File on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "-- For use with the 'mitre' MySQL database",
        "",
        generate_create_table(),
        generate_data_sources_inserts(data_sources_file)
    ]

    # Write to SQL file
    with open(SQL_FILE, 'w') as f:
        f.write("\n".join(sql_content))

    logger.info(f"Generated {SQL_FILE} successfully.")
    logger.info(f"Import it into your MySQL database with: mysql -u your_username -p mitre < {SQL_FILE}")

if __name__ == "__main__":
    main()