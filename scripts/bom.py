import os
import shutil
import subprocess
from urllib.parse import unquote_plus

from defusedxml.ElementTree import parse
from xbom_lib.blint import BlintGenerator
from xbom_lib.cdxgen import (
    CdxgenGenerator,
    CdxgenImageBasedGenerator,
    CdxgenServerGenerator,
)

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

def create_bom(bom_file, src_dir=".", options=None):
    options = options or {}
    project_type = options.get("project_type", [])
    bom_engine = options.get("bom_engine", "")

    if bom_engine == "BlintGenerator":
        blint_lib = BlintGenerator(src_dir, bom_file, options=options)
        bom_result = blint_lib.generate()
        return bom_result.success and os.path.exists(bom_file)

    cdxgen_server = options.get("cdxgen_server")
    cdxgen_lib = CdxgenServerGenerator if cdxgen_server else CdxgenGenerator

    if bom_engine == "CdxgenImageBasedGenerator" or (
        bom_engine == "auto" and shutil.which(os.getenv("DOCKER_CMD", "docker"))
    ):
        cdxgen_lib = CdxgenImageBasedGenerator

    bom_result = cdxgen_lib(src_dir, bom_file, options=options).generate()
    return bom_result.success and os.path.exists(bom_file)

def generate_sbom_with_cdxgen(src_dir=".", output_file="sbom.json"):
    print("Generating SBOM")

    abs_src = os.path.abspath(src_dir)
    abs_out = os.path.abspath(output_file)

    # Папка, в которую сохраняем результат
    out_dir = os.path.dirname(abs_out)
    out_filename = os.path.basename(abs_out)

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
        subprocess.run(docker_args, check=True)
        print(f"[✔] SBOM saved: {abs_out}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[✖] SBOM generation failure: {e}")
        return False