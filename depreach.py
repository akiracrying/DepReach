
import re
import argparse
import os

from scripts.bom import generate_sbom_with_cdxgen
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
        return f"{first_line} [link={link}]read full[/link]"
    else:
        return f"{first_line} [dim](read full)[/dim]"

def print_vulns(vulns: list[dict]):
    console = Console(width=300)  # Можно увеличить, если хочешь шире

    table = Table(title="Vulnerabilities Report", box=box.SQUARE, padding=(0, 1), show_lines=True)

    if not vulns:
        console.print("[bold yellow]No vulnerabilities found.[/bold yellow]")
        return

    # name_in_dict, pretty_header, width, no_wrap
    columns = [
        ("package", "Package", None, True),
        ("installed_version", "Installed version", None, True),
        ("purl", "PURL", None, True),
        ("cve", "CVE", None, True),
        ("severity", "Severity", None, True),
        ("score", "CVSS Score", None, True),
        ("description", "Description", 60, False),  # только description переносим
        ("affected_version", "Affected version", None, True),
        ("CWE", "CWE", None, True),
        ("references", "References", None, False),

    ]

    for key, header, width, nowrap in columns:
        table.add_column(
            header,
            style="bold",
            width=width,  # None значит авто
            no_wrap=nowrap,
            overflow="ellipsis" if nowrap else "fold",
        )

    for vuln in vulns:
        row = []
        for key, *_ in columns:
            val = str(vuln.get(key, ""))
            if key == "description":
                desc_link = vuln.get("ref") or None  # можно доставать ссылку из reference
                val = format_description(val, desc_link)
            row.append(val)
        table.add_row(*row)

    console.print(table)

def check_requirements():
    ...

if __name__ == "__main__":
    """
    SCA Scanner with reachability analysis
    """
    parser = argparse.ArgumentParser(description="DepReach — Next Gen SCA analyzer")
    parser.add_argument("--input", "-i", required=True, help="Path to source code directory")
    parser.add_argument("--output", "-o", required=True, help="Path to output result file (JSON)")

    args = parser.parse_args()

    src_dir = args.input
    output_file = args.output

    # Имя sbom файла рядом с output, с именем {project_name}_sbom.json
    project_name = os.path.basename(os.path.normpath(src_dir))
    output_dir = os.path.dirname(output_file)
    sbom_file = os.path.join(output_dir, f"{project_name}_sbom.json")

    if show_logo():
        print("\n")
        update_vdb()
        generate_sbom_with_cdxgen(src_dir, sbom_file)
        vulns = check_vulnerabilities_from_sbom(src_dir, sbom_file)

        # выводим в консоль красиво
        print_vulns(vulns)

        # сохраняем в файл
        os.makedirs(output_dir, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            import json
            json.dump(vulns, f, indent=2, ensure_ascii=False)