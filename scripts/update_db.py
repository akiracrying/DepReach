import logging

from vdb.lib import config, db6 as db_lib
from vdb.lib.orasclient import download_image

logger = logging.getLogger(__name__)


def update_vdb(silent: bool = False):
    """
    Проверяет актуальность базы данных уязвимостей и обновляет её при необходимости.
    silent: не выводить сообщения (для вывода через спиннер в CLI).
    """
    VDB_AGE_HOURS = 8  # Пороговое значение возраста базы в часах для обновления

    # if db_lib.needs_update(days=0, hours=VDB_AGE_HOURS, default_status=False):
    if db_lib.needs_update():
        if not silent:
            print("Updating Vulnerabilities Database...")
        try:
            if download_image(config.VDB_DATABASE_URL, config.DATA_DIR):
                logger.info("Vulnerability database updated from %s", config.VDB_DATABASE_URL)
            else:
                logger.warning("Vulnerability database update reported failure")
        except Exception as e:
            logger.error("Ошибка при обновлении базы данных: %s", e)
    else:
        logger.info("Vulnerability database is up to date")