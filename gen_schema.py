import json
from genson import SchemaBuilder

# Load the JSON data from the file
with open('config.json', 'r') as file:
    json_data = json.load(file)

# Initialize the schema builder
builder = SchemaBuilder()
builder.add_object(json_data)

# Generate the schema
schema = builder.to_schema()

# Save the schema to a file
with open('schema.json', 'w') as schema_file:
    json.dump(schema, schema_file, indent=2)    