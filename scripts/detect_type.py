import os

ignore_directories = []

def is_binary_string(content):
    """
    Method to check if the given content is a binary string
    """
    textchars = bytearray(
        {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}
    )
    return bool(content.translate(None, textchars))


def is_exe(src):
    """
    Detect if the source is a binary file

    :param src: Source path
    :return True if binary file. False otherwise.
    """
    if os.path.isfile(src):
        try:
            return is_binary_string(open(src, "rb").read(1024))
        except Exception:
            return False
    return False

def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories

    :param dirs: Directories to ignore
    :return: Filtered directory list
    """
    [
        dirs.remove(d)
        for d in list(dirs)
        if d.lower() in ignore_directories or d.startswith(".")
    ]
    return dirs

def find_python_reqfiles(path):
    """
    Method to find python requirements files

    :param path: Project directory
    :return: List of python requirement files
    """
    result = []
    req_files = [
        "requirements.txt",
        "Pipfile",
        "poetry.lock",
        "Pipfile.lock",
        "conda.yml",
        "pyproject.toml",
    ]
    for root, dirs, files in os.walk(path):
        filter_ignored_dirs(dirs)
        result.extend(os.path.join(root, name) for name in req_files if name in files)
    return result

def find_files(src, src_ext_name, quick=False, filter_dirs=True):
    """
    Method to find files with given extension

    :param src: source directory to search
    :param src_ext_name: type of source file
    :param quick: only return first match found
    :param filter_dirs: filter out ignored directories
    """
    result = []
    for root, dirs, files in os.walk(src):
        if filter_dirs:
            filter_ignored_dirs(dirs)
        for file in files:
            if file == src_ext_name or file.endswith(src_ext_name):
                result.append(os.path.join(root, file))
                if quick:
                    return result
    return result

def detect_project_type(src_dir):
    """Detect project type by looking for certain files

    :param src_dir: Source directory
    :return List of detected types
    """
    # container image support
    if (
        "docker.io" in src_dir
        or "quay.io" in src_dir
        or ":latest" in src_dir
        or "@sha256" in src_dir
        or src_dir.endswith(".tar")
        or src_dir.endswith(".tar.gz")
    ):
        return ["docker"]
    # Check if the source is an exe file. Assume go for all binaries for now
    if is_exe(src_dir):
        return ["go", "binary"]
    project_types = []
    if find_python_reqfiles(src_dir) or find_files(src_dir, ".py", quick=True):
        project_types.append("python")
    if find_files(src_dir, "pom.xml", quick=True) or find_files(
        src_dir, ".gradle", quick=True
    ):
        project_types.append("java")
    if find_files(src_dir, ".gradle.kts", quick=True):
        project_types.append("kotlin")
    if find_files(src_dir, "build.sbt", quick=True):
        project_types.append("scala")
    if (
        find_files(src_dir, "package.json", quick=True)
        or find_files(src_dir, "yarn.lock", quick=True)
        or find_files(src_dir, "rush.json", quick=True)
    ):
        project_types.append("nodejs")
    if find_files(src_dir, "go.sum", quick=True) or find_files(
        src_dir, "Gopkg.lock", quick=True
    ):
        project_types.append("go")
    if find_files(src_dir, "Cargo.lock", quick=True):
        project_types.append("rust")
    if find_files(src_dir, "composer.json", quick=True):
        project_types.append("php")
    if find_files(src_dir, ".csproj", quick=True):
        project_types.append("dotnet")
    if find_files(src_dir, "Gemfile", quick=True) or find_files(
        src_dir, "Gemfile.lock", quick=True
    ):
        project_types.append("ruby")
    if find_files(src_dir, "deps.edn", quick=True) or find_files(
        src_dir, "project.clj", quick=True
    ):
        project_types.append("clojure")
    if find_files(src_dir, "conan.lock", quick=True) or find_files(
        src_dir, "conanfile.txt", quick=True
    ):
        project_types.append("cpp")
    if find_files(src_dir, "pubspec.lock", quick=True) or find_files(
        src_dir, "pubspec.yaml", quick=True
    ):
        project_types.append("dart")
    if find_files(src_dir, "cabal.project.freeze", quick=True):
        project_types.append("haskell")
    if find_files(src_dir, "mix.lock", quick=True):
        project_types.append("elixir")
    if find_files(
        os.path.join(src_dir, ".github", "workflows"),
        ".yml",
        quick=True,
        filter_dirs=False,
    ):
        project_types.append("github")
    # jars
    if "java" not in project_types and find_files(src_dir, ".jar", quick=True):
        project_types.append("jar")
    # Jenkins plugins or plain old jars
    if "java" not in project_types and find_files(src_dir, ".hpi", quick=True):
        project_types.append("jenkins")
    if find_files(src_dir, ".yml", quick=True) or find_files(
        src_dir, ".yaml", quick=True
    ):
        project_types.append("yaml-manifest")
    return project_types
