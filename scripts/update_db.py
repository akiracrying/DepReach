import logging

from vdb.lib import config, db6 as db_lib
from vdb.lib.orasclient import download_image

logger = logging.getLogger(__name__)


def update_vdb(silent: bool = False):
    """Check VDB freshness and update if needed. silent: no print (for CLI spinner)."""
    VDB_AGE_HOURS = 8

    if db_lib.needs_update():
        if not silent:
            print("Updating Vulnerabilities Database...")
        try:
            if download_image(config.VDB_DATABASE_URL, config.DATA_DIR):
                logger.info("Vulnerability database updated from %s", config.VDB_DATABASE_URL)
            else:
                logger.warning("Vulnerability database update reported failure")
        except Exception as e:
            logger.error("VDB update failed: %s", e)
    else:
        logger.info("Vulnerability database is up to date")