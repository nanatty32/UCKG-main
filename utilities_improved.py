import os
import json
import hashlib
import subprocess
import sqlite3
from config import LOGGER, vol_file_path
from graph_updater import graph_updater
from process import ontology_updater
import xml.etree.ElementTree as ET
from typing import List, Union


def calculate_file_hash(file_path: str) -> str:
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
    except FileNotFoundError:
        LOGGER.error(f"File {file_path} not found.")
        # Better error handling: Added exception for missing file
        return ""
    return sha256_hash.hexdigest()


def write_file(filename: str, data: dict) -> None:
    """Write JSON data to a file."""
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    except IOError as e:
        LOGGER.error(f"Error writing to {filename}: {e}")
        # Better error handling: Detailed error message for file I/O


def call_mapper_update(datasource: str) -> bool:
    """Call the RML mapper update for the given data source."""
    jar_path = "./rml_mapper/mapper.jar"
    output_file = os.path.join(os.getenv('VOL_PATH', './output'), "out.ttl")
    
    # DRY principle: Replaced redundant code for mapping file selection with a dictionary.
    mapping_files = {
        "cve": "./rml_mapper/cve/cve_rml.ttl",
        "cwe": "./rml_mapper/cwe/cwe_rml.ttl",
        "d3fend": "./rml_mapper/d3fend/d3fend_rml.ttl",
        "attack": "./rml_mapper/attack/attack_rml.ttl"
    }
    
    mapping_file = mapping_files.get(datasource)
    
    if not mapping_file:
        LOGGER.error(f"Invalid data source: {datasource}")
        # Logging consistency: Standardized error message format.
        return False

    command = ["java", "-jar", jar_path, "-m", mapping_file, "-s", "turtle"]

    try:
        with open(output_file, "w") as file:
            process = subprocess.Popen(command, stdout=file, stderr=subprocess.PIPE)
            _, stderr = process.communicate()
            if process.returncode != 0:
                LOGGER.error(f"Error running RML mapping: {stderr.decode()}")
                return False
            LOGGER.info(f"Command executed successfully, output saved to {output_file}")
            # Logging consistency: Unified success and error messages format.
            return True
    except Exception as e:
        LOGGER.error(f"Error in mapper update: {e}")
        # Better error handling: Captured all exceptions and provided informative error messages.
        return False


def call_ontology_updater() -> None:
    """Update the ontology and then update the graph if successful."""
    if ontology_updater.update_ontology():
        LOGGER.info("Ontology updated successfully. Inserting into the DB...")
        graph_updater.update_graph()
    else:
        LOGGER.error("Failed to update ontology.")
        # Logging consistency: Provided informative logs for both success and failure.


def format_datetime_string(datetime_string: str) -> str:
    """Format datetime string by splitting date, time, and milliseconds."""
    try:
        date_part, time_part = datetime_string.split(" ")
        seconds_part, milliseconds_part = time_part.split(".")
        milliseconds_part = milliseconds_part[:3]
        return f"{date_part}T{seconds_part}.{milliseconds_part}"
    except ValueError:
        LOGGER.error(f"Invalid datetime string format: {datetime_string}")
        # Better error handling: Catch incorrect datetime formats and log the error.
        return datetime_string


def get_cwe_id_list() -> List[str]:
    """Extract CWE IDs from the XML file and return a list of formatted CWE IDs."""
    xml_file_path = './rml_mapper/cwe_dict.xml'
    target_path = {
        'Weaknesses': './{http://cwe.mitre.org/cwe-7}Weaknesses',
        'Weakness': './{http://cwe.mitre.org/cwe-7}Weakness',
        'ID': './ID'
    }

    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        LOGGER.error(f"Error parsing XML file: {e}")
        # Better error handling: Added exception handling for XML parsing errors.
        return []

    extracted_ids = []
    for weaknesses in root.findall(target_path['Weaknesses']):
        for weakness in weaknesses.findall(target_path['Weakness']):
            id_value = weakness.get('ID')
            if id_value:
                extracted_ids.append(f"CWE-{id_value.strip()}")

    return extracted_ids


def check_status(data_source: str) -> Union[int, None]:
    """Check the status of various data sources (cve, cwe, d3fend, attack, capec)."""
    # DRY principle: Used a dictionary to avoid repeating the file paths for each data source.
    db_file_map = {
        "cve": './data/cve_database.db',
        "d3fend": os.path.join(vol_file_path, 'd3fend.json'),
        "attack": os.path.join(vol_file_path, 'attack.json'),
        "capec": os.path.join(vol_file_path, 'capec.json')
    }

    if data_source == "cve":
        return _check_cve_status(db_file_map["cve"])
    elif data_source in ["d3fend", "attack", "capec"]:
        return 0 if os.path.exists(db_file_map[data_source]) else 3
    else:
        LOGGER.error(f"Invalid data source: {data_source}")
        # Logging consistency: Standardized error messages for invalid data sources.
        return None


def _check_cve_status(db_file_path: str) -> int:
    """Check the status of the CVE data source."""
    if not os.path.exists(db_file_path):
        LOGGER.error(f"CVE database not found: {db_file_path}")
        # Better error handling: Provided informative error message for missing database file.
        return 3

    try:
        with sqlite3.connect(db_file_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_meta'")
            table_exists = cursor.fetchone()
            if table_exists:
                cursor.execute("SELECT init_finished FROM cve_meta")
                row = cursor.fetchone()
                return row[0] if row else 3
            return 3
    except sqlite3.Error as e:
        LOGGER.error(f"Database error: {e}")
        # Better error handling: Added database-specific error messages.
        return 3
