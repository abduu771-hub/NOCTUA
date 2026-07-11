import os
import json

def generate_inventory():
    try:
        with open('ast_dump.json', 'r', encoding='utf-8') as f:
            ast_data = json.load(f)
    except Exception:
        ast_data = {}

    with open('inventory.md', 'w', encoding='utf-8') as out:
        out.write("# SIEM-AI Technical Inventory\n\n")

        for root, dirs, files in os.walk('.'):
            if '.venv' in root or 'node_modules' in root or '.git' in root or '__pycache__' in root or '.cursor' in root:
                continue

            folder_path = root.replace('\\', '/')
            if folder_path == '.':
                folder_path = '/'
            out.write(f"## Folder: {folder_path}\n\n")
            out.write("**Purpose:** Container for files in this directory.\n")
            out.write("**Inputs:** Files and subdirectories.\n")
            out.write("**Outputs:** Structure of components.\n")
            out.write("**Dependencies:** Parent directory.\n")
            out.write("**Execution flow:** N/A (Directory)\n\n")

            for file in files:
                if file in ['ast_dump.json', 'parse_ast.py', 'build_inventory.py', 'inventory.md']:
                    continue
                path = os.path.join(root, file)
                path_norm = path.replace('\\', '/')
                out.write(f"### File: {path_norm}\n\n")

                if file.endswith('.py'):
                    data = ast_data.get(path, {})
                    purpose = data.get('purpose', 'Python module')
                    if purpose == "No module docstring":
                        purpose = "Python source file."
                    deps = ", ".join(data.get('dependencies', [])) or "None"
                    
                    # Compute inputs and outputs from classes/functions
                    inputs_list = []
                    outputs_list = []
                    exec_flow = []
                    
                    for cls in data.get('classes', []):
                        for m in cls.get('methods', []):
                            if m['inputs']:
                                inputs_list.append(f"{cls['name']}.{m['name']}({', '.join(m['inputs'])})")
                            if m['outputs'] and m['outputs'] != 'None':
                                outputs_list.append(f"{cls['name']}.{m['name']} -> {m['outputs']}")
                            exec_flow.append(f"Class {cls['name']} defines method {m['name']}.")
                    
                    for f in data.get('functions', []):
                        if f['inputs']:
                            inputs_list.append(f"{f['name']}({', '.join(f['inputs'])})")
                        if f['outputs'] and f['outputs'] != 'None':
                            outputs_list.append(f"{f['name']} -> {f['outputs']}")
                        exec_flow.append(f"Function {f['name']} defined.")
                        
                    inputs = "; ".join(inputs_list) or "None"
                    outputs = "; ".join(outputs_list) or "None"
                    flow = " ".join(exec_flow) or "Sequential execution of module level code."

                    out.write(f"**Purpose:** {purpose}\n")
                    out.write(f"**Inputs:** {inputs}\n")
                    out.write(f"**Outputs:** {outputs}\n")
                    out.write(f"**Dependencies:** {deps}\n")
                    out.write(f"**Execution flow:** {flow}\n\n")

                elif file.endswith('.html'):
                    out.write("**Purpose:** HTML View template.\n")
                    out.write("**Inputs:** User interactions, frontend routing.\n")
                    out.write("**Outputs:** Rendered DOM elements.\n")
                    out.write("**Dependencies:** Linked CSS/JS files.\n")
                    out.write("**Execution flow:** Rendered by browser upon navigation.\n\n")

                elif file.endswith('.js'):
                    out.write("**Purpose:** Client-side JavaScript logic.\n")
                    out.write("**Inputs:** DOM events, API responses.\n")
                    out.write("**Outputs:** DOM updates, API requests.\n")
                    out.write("**Dependencies:** Other JS modules, HTML DOM.\n")
                    out.write("**Execution flow:** Event-driven or executed on load.\n\n")

                elif file.endswith('.css'):
                    out.write("**Purpose:** Cascading Style Sheets for UI styling.\n")
                    out.write("**Inputs:** HTML elements matching selectors.\n")
                    out.write("**Outputs:** Styled DOM.\n")
                    out.write("**Dependencies:** HTML templates.\n")
                    out.write("**Execution flow:** Applied by browser rendering engine.\n\n")

                elif file.endswith('.yml') or file.endswith('.yaml'):
                    out.write("**Purpose:** Configuration file (YAML).\n")
                    out.write("**Inputs:** User/System defined settings.\n")
                    out.write("**Outputs:** Config values consumed by application.\n")
                    out.write("**Dependencies:** Application parser.\n")
                    out.write("**Execution flow:** Parsed during initialization.\n\n")

                elif file.endswith('.json'):
                    out.write("**Purpose:** Data/Configuration file (JSON).\n")
                    out.write("**Inputs:** JSON structure.\n")
                    out.write("**Outputs:** Data consumed by app/package manager.\n")
                    out.write("**Dependencies:** System parsing JSON.\n")
                    out.write("**Execution flow:** Parsed when required.\n\n")

                elif file.endswith('.md'):
                    out.write("**Purpose:** Markdown documentation.\n")
                    out.write("**Inputs:** Text content.\n")
                    out.write("**Outputs:** Rendered documentation.\n")
                    out.write("**Dependencies:** Markdown viewer.\n")
                    out.write("**Execution flow:** Read by user.\n\n")

                elif file.endswith('.conf'):
                    out.write("**Purpose:** Configuration file.\n")
                    out.write("**Inputs:** System settings.\n")
                    out.write("**Outputs:** Config values.\n")
                    out.write("**Dependencies:** Application requiring conf.\n")
                    out.write("**Execution flow:** Read at startup.\n\n")
                    
                else:
                    out.write("**Purpose:** Miscellaneous file.\n")
                    out.write("**Inputs:** N/A\n")
                    out.write("**Outputs:** N/A\n")
                    out.write("**Dependencies:** N/A\n")
                    out.write("**Execution flow:** N/A\n\n")

if __name__ == "__main__":
    generate_inventory()
