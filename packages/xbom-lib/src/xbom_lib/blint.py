import os
import shutil
import tempfile

from xbom_lib import BOMResult, XBOMGenerator

BLINT_AVAILABLE = False
try:
    from blint.lib.runners import run_sbom_mode
    from blint.config import BlintOptions, BLINTDB_IMAGE_URL
    from blint.lib.utils import blintdb_setup

    BLINT_AVAILABLE = True
except ImportError:
    pass


class BlintGenerator(XBOMGenerator):
    """
    Generate xBOM using blint
    """

    def generate(self) -> BOMResult:
        """
        Generate the BOM using blint.
        """
        if not BLINT_AVAILABLE:
            return BOMResult(success=False,
                             command_output="The required packages for binary SBOM generation are not available. Reinstall depscan using `pip install owasp-depscan[all]`.")
        src_dir = self.source_dir
        bom_file = self.bom_file
        temp_reports_dir = tempfile.mkdtemp(prefix="blint-reports-", dir=os.getenv("DEPSCAN_TEMP_DIR"))
        os.environ["BLINT_TEMP_DIR"] = temp_reports_dir
        blint_options = BlintOptions(deep_mode=True, sbom_mode=True, db_mode=True,
                                     no_reviews=True, no_error=True, quiet_mode=True,
                                     src_dir_image=src_dir.split(","), stdout_mode=False,
                                     reports_dir=temp_reports_dir, use_blintdb=True,
                                     image_url=self.options.get("blintdb_image_url", BLINTDB_IMAGE_URL),
                                     sbom_output=bom_file)
        blintdb_setup(blint_options)
        sbom = run_sbom_mode(blint_options)
        shutil.rmtree(temp_reports_dir, ignore_errors=True)
        return BOMResult(success=True, bom_obj=sbom)
