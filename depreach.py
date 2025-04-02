from scripts.update_db import update_vdb
from colorama import Fore, Style
from scripts.bom import generate_sbom_with_cdxgen
from scripts.composition_analysis import check_vulnerabilities_from_sbom


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

if __name__ == "__main__":
    if show_logo():
        print("\n")
        update_vdb()
        #generate_sbom_with_cdxgen("tests/test1", "tests/results/test1.json")
        check_vulnerabilities_from_sbom("tests/test1", "tests/results/test1.json")
