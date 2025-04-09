import ast
import inspect
import tempfile

import requests
import re
import json
from collections import defaultdict
import importlib

import os
import subprocess
import json

def extract_commit_links(references: list[str]) -> list[str]:
    return [ref for ref in references if "/commit/" in ref]

def get_diff(url):
    if not url.endswith('.diff'):
        url += '.diff'
    response = requests.get(url)
    return response.text

def extract_functions_from_diff(diff_text):
    pattern = re.compile(r'def (\w+)\(')
    return set(pattern.findall(diff_text))

def parse_callgraph(file_path):
    with open(file_path) as f:
        data = json.load(f)

    usage = defaultdict(set)
    for full_func_name in data.keys():
        pkg_name, func_name = full_func_name.split(".", 1)
        usage[pkg_name].add(func_name)

    return dict(usage)

def check_reachability(vuln_references, component_usage):
    commit_links = extract_commit_links(vuln_references)

    reachability_report = {}
    if not commit_links:
        return {
            "is_reachable": "Unknown"
        }
    for link in commit_links:
        component_name = link.split("/")[4]  # имя репозитория из ссылки
        diff_text = get_diff(link)
        changed_funcs = extract_functions_from_diff(diff_text)

        used_funcs = component_usage.get(component_name, set())

        intersection = changed_funcs & used_funcs

        reachability_report[link] = {
            "changed_funcs": list(changed_funcs),
            "reachable_funcs": list(intersection),
            "is_reachable": bool(intersection)
        }

    return reachability_report


def get_imported_functions(module_name: str) -> set[str]:
    functions = set()
    try:
        module = importlib.import_module(module_name)
        for name, obj in inspect.getmembers(module):
            if inspect.isfunction(obj):
                functions.add(name)
            elif inspect.isclass(obj):
                for method_name, _ in inspect.getmembers(obj, inspect.isfunction):
                    functions.add(f"{obj.__name__}.{method_name}")
    except ImportError:
        print(f"Warning: Could not import module {module_name}")
    return functions


def extract_library_function_calls(directory: str) -> dict[str, set[str]]:
    result = {}
    imports = {}
    module_imports = {}  # Сопоставление коротких имен с полными именами модулей

    # Сначала собираем все импорты
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                with open(path, 'r', encoding='utf-8') as f:
                    try:
                        tree = ast.parse(f.read())
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Import):
                                for alias in node.names:
                                    full_name = alias.name
                                    short_name = alias.asname or alias.name.split('.')[0]
                                    module_imports[short_name] = full_name
                            elif isinstance(node, ast.ImportFrom):
                                module = node.module
                                level = node.level  # Для относительных импортов
                                for alias in node.names:
                                    full_name = f"{module}.{alias.name}" if level == 0 else f"{'.' * level}{module}.{alias.name}"
                                    short_name = alias.asname or alias.name
                                    module_imports[short_name] = full_name
                    except Exception as e:
                        print(f"Error parsing imports in {path}: {e}")

    # Затем собираем вызовы функций и группируем по модулям
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                with open(path, 'r', encoding='utf-8') as f:
                    try:
                        tree = ast.parse(f.read())
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                module_name = None
                                func_name = None

                                if isinstance(node.func, ast.Attribute):
                                    # Обработка методов и атрибутов: obj.method()
                                    base = ast.unparse(node.func.value)
                                    base_parts = base.split('.')

                                    # Ищем корневой модуль в цепочке атрибутов
                                    for part in base_parts:
                                        if part in module_imports:
                                            module_name = module_imports[part].split('.')[0]
                                            break

                                    if module_name:
                                        func_name = node.func.attr

                                elif isinstance(node.func, ast.Name):
                                    # Обработка простых вызовов: func()
                                    if node.func.id in module_imports:
                                        module_name = module_imports[node.func.id].split('.')[0]
                                        func_name = node.func.id

                                if module_name and func_name:
                                    if module_name not in result:
                                        result[module_name] = set()
                                    result[module_name].add(func_name)
                    except Exception as e:
                        print(f"Error parsing calls in {path}: {e}")

    return result