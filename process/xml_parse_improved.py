import xml.etree.ElementTree as ET
import json
import os

# Function to parse XML file and extract specific elements
def extract_specific_elements(xml_file, target_path):
    try:
        # Parse the XML file
        tree = ET.parse(xml_file)
        root = tree.getroot()

        # List to hold the extracted elements
        extracted_elements = []

        # Navigate through the XML tree and extract elements
        for weaknesses in root.findall(target_path['Weaknesses']):
            for weakness in weaknesses.findall(target_path['Weakness']):
                id_value = weakness.get('ID')
                if id_value is not None:
                    extracted_elements.append(id_value)

        return extracted_elements

    except ET.ParseError as e:
        print(f"Error parsing the XML file: {e}")
        return []
    except FileNotFoundError:
        print(f"File not found: {xml_file}")
        return []

# Specify the path to your XML file
xml_file_path = '../data/cwe/cwe_dict.xml'

# Ensure the file exists before parsing
if not os.path.exists(xml_file_path):
    print(f"File not found: {xml_file_path}")
    exit(1)

# Define the path to the target elements
target_path = {
    'Weaknesses': './{http://cwe.mitre.org/cwe-7}Weaknesses',
    'Weakness': './{http://cwe.mitre.org/cwe-7}Weakness',
    'ID': './ID'
}

# Extract the specific elements
extracted_ids = extract_specific_elements(xml_file_path, target_path)

if not extracted_ids:
    print("No IDs extracted, exiting.")
    exit(1)

# Structure the extracted data into JSON format
cwes = {"cwes": [{"cwe": {"id": f"CWE-{id}"}} for id in extracted_ids]}

# Write the JSON data to a file
output_json_path = "../mapping/cwe/cwes.json"
with open(output_json_path, "w") as json_file:
    json.dump(cwes, json_file, indent=4)

print(f"Extracted data written to {output_json_path}")
