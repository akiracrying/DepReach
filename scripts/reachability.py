import ast
import inspect
import tempfile

import requests
import re
from collections import defaultdict
import importlib

import os
import json

import shutil
import tarfile

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

def check_reachability(vuln_references, component_usage, project_call_graph=None, purl: str = None, imports_data = "data"):
    commit_links = extract_commit_links(vuln_references)
    commit_links = set(commit_links)
    reachability_report = {}

    if not commit_links:
        return {
            "is_reachable": "Unknown"
        }

    lib_call_graph = None
    if purl:
        try:
            #print(f"[info] Downloading source for {purl}")
            lib_dir = download_purl_source(purl, imports_data)
            #print(f"[info] Building call graph for downloaded library: {lib_dir}")
            lib_call_graph = build_call_graph(lib_dir)
        except Exception as e:
            pass
            #print(f"[warn] Failed to download/build graph for {purl}: {e}")

    for link in commit_links:
        component_name = link.split("/")[4]  # имя репозитория из ссылки
        diff_text = get_diff(link)
        changed_funcs = extract_functions_from_diff(diff_text)

        used_funcs = component_usage.get(component_name, set())
        direct_reach = changed_funcs & used_funcs
        graph_reach = set()

        # Проверка достижимости по графу проекта
        if project_call_graph:
            for target in changed_funcs:
                if is_func_reachable(used_funcs, target, project_call_graph):
                    graph_reach.add(target)

        # Проверка достижимости внутри самой библиотеки (если есть lib_call_graph)
        lib_graph_reach = set()
        if lib_call_graph:
            for used_func in used_funcs:
                for changed in changed_funcs:
                    if is_func_reachable({used_func}, changed, lib_call_graph):
                        lib_graph_reach.add(changed)

        reachability_report[link] = {
            "changed_funcs": list(changed_funcs),
            "reachable_funcs": list(direct_reach),
            "reachable_via_graph": list(graph_reach),
            "reachable_via_library": list(lib_graph_reach),
            "is_reachable": bool(direct_reach or graph_reach or lib_graph_reach)
        }

    return reachability_report

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

def download_purl_source(purl: str, target_dir: str) -> str:
    """
    Скачивает исходники библиотеки по PURL (только PyPI).
    Пример purl: "pkg:pypi/requests@2.31.0"
    Возвращает путь к распакованной папке с кодом.
    """
    match = re.match(r"pkg:pypi/([^@]+)@([^@]+)", purl)
    if not match:
        raise ValueError(f"Invalid PURL format: {purl}")

    package, version = match.groups()
    #print(f"[INFO] Downloading {package}=={version}...")

    api_url = f"https://pypi.org/pypi/{package}/{version}/json"
    resp = requests.get(api_url)
    if resp.status_code != 200:
        raise ValueError(f"Package not found on PyPI: {package}=={version}")

    data = resp.json()
    sdist_url = None
    for file_info in data["urls"]:
        if file_info["packagetype"] == "sdist" and file_info["filename"].endswith(".tar.gz"):
            sdist_url = file_info["url"]
            break

    if not sdist_url:
        raise ValueError(f"No .tar.gz sdist found for {package}=={version}")

    archive_path = os.path.join(tempfile.gettempdir(), f"{package}-{version}.tar.gz")
    with requests.get(sdist_url, stream=True) as r:
        with open(archive_path, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

    extract_path = os.path.join(target_dir, f"{package}-{version}")
    os.makedirs(extract_path, exist_ok=True)

    with tarfile.open(archive_path, "r:gz") as tar:
        def is_within_directory(directory, target):
            abs_directory = os.path.abspath(directory)
            abs_target = os.path.abspath(target)
            return os.path.commonpath([abs_directory]) == os.path.commonpath([abs_directory, abs_target])

        def safe_extract(tar_obj, path=".", members=None, *, numeric_owner=False):
            for member in tar_obj.getmembers():
                member_path = os.path.join(path, member.name)
                if not is_within_directory(path, member_path):
                    raise Exception("Attempted Path Traversal in Tar File")

            tar_obj.extractall(path, members, numeric_owner=numeric_owner)

        safe_extract(tar, extract_path)

    # Путь к директории внутри архива (обычно requests-2.31.0/)
    inner_dirs = os.listdir(extract_path)
    if len(inner_dirs) == 1:
        return os.path.join(extract_path, inner_dirs[0])
    return extract_path

def build_call_graph(directory: str) -> dict[str, set[str]]:
    """
    Строит граф вызовов между функциями внутри проекта.
    Ключ — имя функции, значение — множество функций, которые она вызывает.
    """
    call_graph = {}

    for root, _, files in os.walk(directory):
        for file in files:
            if not file.endswith('.py'):
                continue

            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read())
            except Exception as e:
                #print(f"[!] Failed to parse {path}: {e}")
                continue

            func_defs = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

            for func_name, func_node in func_defs.items():
                called = set()
                for node in ast.walk(func_node):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            called.add(node.func.id)
                        elif isinstance(node.func, ast.Attribute):
                            called.add(node.func.attr)
                call_graph[func_name] = called

    return call_graph

def is_func_reachable(start_funcs: set[str], target_func: str, call_graph: dict[str, set[str]]) -> bool:
    """
    Проверяет, достижима ли уязвимая функция target_func из любой функции в start_funcs.
    """
    visited = set()
    stack = list(start_funcs)

    while stack:
        current = stack.pop()
        if current == target_func:
            return True
        if current not in visited:
            visited.add(current)
            stack.extend(call_graph.get(current, []))

    return False
