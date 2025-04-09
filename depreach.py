
import re
import argparse
import os
from logging import DEBUG

from scripts.bom import generate_sbom_with_cdxgen
from scripts.detect_type import detect_project_type
from scripts.reachability import check_reachability, extract_library_function_calls #create_codeql_database, extract_project_functions_with_codeql
from scripts.update_db import update_vdb
from colorama import Fore, Style

from scripts.composition_analysis import check_vulnerabilities_from_sbom
from rich.console import Console
from rich.table import Table
from rich import box
from rich.markup import escape

def show_logo():
    logo_dep = r"""
______ ___________              
|  _  \  ___| ___ \             
| | | | |__ | |_/ /             
| | | |  __||  __/              
| |/ /| |___| |                 
|___/ \____/\_|  
  """.rstrip()
    logo_reach = r"""
______ _____  ___  _____  _   _ 
| ___ \  ___|/ _ \/  __ \| | | |
| |_/ / |__ / /_\ \ /  \/| |_| |
|    /|  __||  _  | |    |  _  |
| |\ \| |___| | | | \__/\| | | |
\_| \_\____/\_| |_/\____/\_| |_/
    """.rstrip()

    print(Fore.BLUE + logo_dep + Fore.RED + logo_reach + Style.RESET_ALL)

    return True


def format_description(desc: str, link: str = None) -> str:
    if not desc:
        return ""

    # Превращаем \n, \t и т.д. в реальные символы
    try:
        desc = desc.encode().decode("unicode_escape")
    except Exception:
        pass  # если вдруг строка уже норм

    # Удаляем markdown мусор
    clean = re.sub(r'`+', '', desc)
    clean = re.sub(r'\*+', '', clean)
    clean = re.sub(r'#+\s*', '', clean)
    clean = re.sub(r'\[.*?\]\(.*?\)', '', clean)
    clean = re.sub(r'\n{2,}', '\n', clean)
    clean = clean.strip()

    # Берем первую строку до первого \n
    first_line = clean.split('\n')[0].strip()

    # Экранируем Rich-разметку
    first_line = escape(first_line)

    # Добавляем "читать далее" с ссылкой или без
    if link:
        return f"{first_line}"
    else:
        return f"{first_line}"

def print_vulns(vulns: list[dict]):
    console = Console(width=300)

    table = Table(title="Vulnerabilities Report", box=box.SQUARE, padding=(0, 1), show_lines=True)

    if not vulns:
        console.print("[bold yellow]No vulnerabilities found.[/bold yellow]")
        return

    columns = [
        ("package", "Package", None, True),
        ("installed_version", "Installed version", None, True),
        ("purl", "PURL", None, True),
        ("cve", "CVE", None, True),
        ("severity", "Severity", None, True),
        ("score", "CVSS Score", None, True),
        ("description", "Description", 60, False),
        ("affected_version", "Affected version", None, True),
        ("CWE", "CWE", None, True),
        ("references", "References", None, False),
        ("reachable", "Reachable?", 10, True),  # ⬅️ новая колонка
    ]

    for key, header, width, nowrap in columns:
        table.add_column(
            header,
            style="bold",
            width=width,
            no_wrap=nowrap,
            overflow="ellipsis" if nowrap else "fold",
        )

    MAX_REFS_TO_SHOW = 3

    for vuln in vulns:
        row = []
        for key, *_ in columns:
            if key == "description":
                desc_link = (vuln.get("references") or [None])[0]
                val = format_description(vuln.get(key, ""), desc_link)

            elif key == "references":
                refs = vuln.get(key, [])
                shown = refs[:MAX_REFS_TO_SHOW]
                rest = len(refs) - MAX_REFS_TO_SHOW
                val = "\n".join(f"[link={url}]{url}[/link]" for url in shown)
                if rest > 0:
                    val += f"\n...and {rest} more"

            elif key == "reachable":
                reach = vuln.get("reachability", {})
                if not reach:
                    val = "[dim]—[/dim]"  # если вообще нет данных
                else:
                    lines = []
                    for i, (url, info) in enumerate(reach.items(), 1):
                        if info != "Unknown":
                            mark = "[green]✅[/green]" if info.get("is_reachable") else "[red]❌[/red]"
                        else:
                            mark = "Unknown"
                        #short_url = url.split("/")[-1][:16]  # Можно сделать короче
                        lines.append(f"{i}. {mark}")
                    val = "\n".join(lines)

            else:
                val = str(vuln.get(key, ""))
            row.append(val)
        table.add_row(*row)

    console.print(table)

def check_requirements():
    ...

def dep_reach(args):

    src_dir = args.input
    output_file = args.output
    skip_update = args.skip_update

    project_type = detect_project_type(src_dir)
    if not project_type:
        project_type = "universal"

    DEBUG = False
    if DEBUG:
        commit_url = "https://github.com/pallets/flask/commit/b178e89e4456e777b1a7ac6d7199052d0dfdbbbe"

        # Список функций проекта (получишь через pycg, pyan, или CodeQL)
        project_functions = ["jsonify", "load_json", "get_json"]

        result = check_reachability(commit_url, project_functions)

        print(result)
        exit("DEBUGEXIT")

    # Имя sbom файла рядом с output, с именем {project_name}_sbom.json
    project_name = os.path.basename(os.path.normpath(src_dir))
    output_dir = os.path.dirname(output_file)
    sbom_file = os.path.join(output_dir, f"{project_name}_sbom.json")


    if show_logo():
        print("\n")
        if not skip_update:
            update_vdb()
        generate_sbom_with_cdxgen(src_dir, sbom_file)
        vulns = check_vulnerabilities_from_sbom(src_dir, sbom_file)


        #codeql_db_path = f"{output_dir}/{project_name}_codeql_db" #os.path.join(output_dir, f"{project_name}_codeql_db")

        #success = create_codeql_database(src_dir, codeql_db_path, language=project_type[0])

        #if not success:
        #    print("[!] Failed to create CodeQL database.")
        #    return

        # Извлекаем вызываемые функции из проекта
        project_functions = extract_library_function_calls(src_dir)

        if vulns:
            for vuln in vulns:
                report = check_reachability(vuln["references"], project_functions)
                vuln["reachability"] = report
        else:
            return "No vulnerabilities found."
        # выводим в консоль красиво
        print_vulns(vulns)

        # сохраняем в файл
        os.makedirs(output_dir, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            import json
            json.dump(vulns, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    """
    SCA Scanner with reachability analysis
    """
    parser = argparse.ArgumentParser(description="DepReach — Next Gen SCA analyzer")
    parser.add_argument("--input", "-i", required=True, help="Path to source code directory")
    parser.add_argument("--output", "-o", required=True, help="Path to output result file (JSON)")
    parser.add_argument("--skip-update", action="store_true", help="Skip updating the vulnerability database")

    args = parser.parse_args()

    dep_reach(args)