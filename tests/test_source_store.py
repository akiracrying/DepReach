import io
import tarfile
import zipfile

import pytest

from scripts.source_store import extract_archive


@pytest.mark.parametrize("name", ["../escape.py", "/escape.py", "C:/escape.py", "pkg/file:stream", "pkg/../../escape"])
def test_rejects_archive_paths(tmp_path, name):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as dest:
        dest.writestr(name, "data")
    with pytest.raises(ValueError, match="Unsafe"):
        extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "escape.py").exists()


def test_rejects_tar_symlinks(tmp_path):
    archive = tmp_path / "bad.tar"
    with tarfile.open(archive, "w") as dest:
        member = tarfile.TarInfo("pkg/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../elsewhere"
        dest.addfile(member)
    with pytest.raises(ValueError, match="links"):
        extract_archive(archive, tmp_path / "out")


@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_extracts_regular_source_without_executing_it(tmp_path, kind):
    archive = tmp_path / f"source.{kind}"
    data = b"raise RuntimeError('must never execute')"
    if kind == "tar":
        with tarfile.open(archive, "w") as dest:
            member = tarfile.TarInfo("pkg/mod.py")
            member.size = len(data)
            dest.addfile(member, io.BytesIO(data))
    else:
        with zipfile.ZipFile(archive, "w") as dest:
            dest.writestr("pkg/mod.py", data)
    extract_archive(archive, tmp_path / "out")
    assert (tmp_path / "out/pkg/mod.py").read_bytes() == data


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_internal_link_materialized_without_filesystem_link(tmp_path, kind):
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as dest:
        member = tarfile.TarInfo("pkg/module.py")
        member.size = 4
        dest.addfile(member, io.BytesIO(b"pass"))
        link = tarfile.TarInfo("pkg/tools/module.py")
        link.type = kind
        link.linkname = "../module.py" if kind == tarfile.SYMTYPE else "pkg/module.py"
        dest.addfile(link)
    extract_archive(archive, tmp_path / "out")
    path = tmp_path / "out/pkg/tools/module.py"
    assert path.read_bytes() == b"pass"
    assert not path.is_symlink()
