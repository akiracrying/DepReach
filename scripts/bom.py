import os
import subprocess
import sys
from urllib.parse import unquote_plus

from defusedxml.ElementTree import parse


def parse_bom_ref(bomstr, licenses=None):
    if bomstr:
        bomstr = unquote_plus(bomstr)
    tmpl = bomstr.split("/")
    vendor, name_ver = "", []
    if len(tmpl) >= 2:
        vendor = tmpl[-2].replace("pkg:", "")
        name_ver = tmpl[-1].split("@")
    if len(name_ver) >= 2:
        name, version = name_ver[-2], name_ver[-1].split("?")[0].lstrip("v")
    else:
        name, version = name_ver[0], "*"
    return {"vendor": vendor, "name": name, "version": version, "licenses": licenses}

def get_licenses(ele):
    license_list = []
    namespace = "{http://cyclonedx.org/schema/bom/1.5}"
    for data in ele.findall(f"{namespace}licenses/{namespace}license/{namespace}id"):
        license_list.append(data.text)
    return license_list

def get_package(component_ele, licenses):
    bom_ref = component_ele.attrib.get("bom-ref")
    pkg = {"licenses": licenses, "vendor": "", "name": "", "version": ""}
    if bom_ref and "/" in bom_ref:
        pkg = parse_bom_ref(bom_ref, licenses)
    for ele in component_ele.iter():
        if ele.tag.endswith("group") and ele.text:
            pkg["vendor"] = ele.text
        if ele.tag.endswith("name") and ele.text and not pkg["name"]:
            pkg["name"] = ele.text
        if ele.tag.endswith("version") and ele.text:
            pkg["version"] = ele.text.lstrip("v")
        if ele.tag.endswith("purl") and ele.text and not pkg.get("vendor"):
            pkg["vendor"] = ele.text.split("/")[0].replace("pkg:", "")
    return pkg

def get_pkg_list(xmlfile):
    pkgs = []
    et = parse(xmlfile)
    root = et.getroot()
    for child in root:
        if child.tag.endswith("components"):
            for ele in child.iter():
                if ele.tag.endswith("component"):
                    licenses = get_licenses(ele)
                    pkgs.append(get_package(ele, licenses))
    return pkgs

def _choose_python_provider(src_dir):
    """Choose cyclonedx_py provider: poetry, pipenv, or requirements. Returns (cmd, args)."""
    abs_src = os.path.abspath(src_dir)
    if os.path.isfile(os.path.join(abs_src, "poetry.lock")):
        return "poetry", [abs_src]
    if os.path.isfile(os.path.join(abs_src, "Pipfile")):
        return "pipenv", [abs_src]
    req_files = [
        os.path.join(abs_src, "requirements.txt"),
        os.path.join(abs_src, "requirements", "requirements.txt"),
    ]
    for p in req_files:
        if os.path.isfile(p):
            return "requirements", [p]
    return "requirements", [os.path.join(abs_src, "requirements.txt")]


def generate_sbom_python(src_dir=".", output_file="sbom.json"):
    """Generate SBOM using cyclonedx-py (cyclonedx-bom) — no Docker. Python projects only."""
    abs_src = os.path.abspath(src_dir)
    abs_out = os.path.abspath(output_file)

    if os.path.exists(abs_out):
        try:
            os.remove(abs_out)
        except OSError:
            pass

    provider, provider_args = _choose_python_provider(src_dir)
    cmd = [sys.executable, "-m", "cyclonedx_py", provider] + provider_args + [
        "--outfile", abs_out,
        "--output-format", "JSON",
        "--schema-version", "1.5",
    ]
    try:
        subprocess.run(cmd, cwd=abs_src, check=True, stdin=subprocess.DEVNULL)
        return os.path.exists(abs_out)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def generate_sbom_with_cdxgen(src_dir=".", output_file="sbom.json"):
    abs_src = os.path.abspath(src_dir)
    abs_out = os.path.abspath(output_file)

    # Папка, в которую сохраняем результат
    out_dir = os.path.dirname(abs_out)
    out_filename = os.path.basename(abs_out)

    if os.path.exists(abs_out):
        try:
            os.remove(abs_out)
            print(f"Old SBOM file removed: {abs_out}")
        except Exception as e:
            print(f"Error removing file")
            exit(1)

    # Монтируем две папки в контейнер
    # src_dir -> /src
    # out_dir -> /out
    docker_args = [
        "docker", "run", "--rm",
        "-v", f"{abs_src}:/src",
        "-v", f"{out_dir}:/out",
        "ghcr.io/cyclonedx/cdxgen",
        "/src",                  #  путь к исходникам внутри контейнера
        "-o", f"/out/{out_filename}"  #  путь до выходного файла
    ]

    try:
        subprocess.run(docker_args, check=True, stdin=subprocess.DEVNULL)
        print(f"SBOM saved: {abs_out}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"SBOM generation failure: {e}")
        return False