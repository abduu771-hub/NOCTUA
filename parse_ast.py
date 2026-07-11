import ast
import os
import json

def parse_python_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content)
        
        info = {
            "purpose": ast.get_docstring(tree) or "No module docstring",
            "dependencies": [],
            "classes": [],
            "functions": []
        }
        
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    info["dependencies"].append(n.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for n in node.names:
                    info["dependencies"].append(f"{module}.{n.name}")
            elif isinstance(node, ast.ClassDef):
                cls_info = {
                    "name": node.name,
                    "purpose": ast.get_docstring(node) or "",
                    "methods": []
                }
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) or isinstance(item, ast.AsyncFunctionDef):
                        args = [a.arg for a in item.args.args]
                        returns = ast.unparse(item.returns) if item.returns else "None"
                        cls_info["methods"].append({
                            "name": item.name,
                            "inputs": args,
                            "outputs": returns,
                            "purpose": ast.get_docstring(item) or ""
                        })
                info["classes"].append(cls_info)
            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                args = [a.arg for a in node.args.args] if hasattr(node, 'args') and hasattr(node.args, 'args') else []
                returns = ast.unparse(node.returns) if hasattr(node, 'returns') and node.returns else "None"
                info["functions"].append({
                    "name": node.name,
                    "inputs": args,
                    "outputs": returns,
                    "purpose": ast.get_docstring(node) or ""
                })
        return info
    except Exception as e:
        return {"error": str(e)}

result = {}
for root, dirs, files in os.walk('.'):
    if '.venv' in root or 'node_modules' in root or '.git' in root or '__pycache__' in root:
        continue
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            result[path] = parse_python_file(path)

with open('ast_dump.json', 'w', encoding='utf-8') as f:
    json.dump(result, f, indent=2)
