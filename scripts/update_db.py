import logging
from vdb.lib import config, db6 as db_lib
from vdb.lib.orasclient import download_image

logging.basicConfig(level=logging.INFO)

def update_vdb():
    """
    Проверяет актуальность базы данных уязвимостей и обновляет её при необходимости.
    """
    VDB_AGE_HOURS = 24  # Пороговое значение возраста базы в часах для обновления

    if db_lib.needs_update(days=0, hours=VDB_AGE_HOURS, default_status=False):
        print("Updating Vulnerabilities Database...")
        try:
            if download_image(config.VDB_DATABASE_URL, config.DATA_DIR):
                a = "Good"
                #logging.info("База данных уязвимостей успешно обновлена.")
            else:
                a = "Bad"
                #logging.error("Не удалось обновить базу данных уязвимостей.")
        except Exception as e:
            a = "Good"
            #logging.error(f"Ошибка при обновлении базы данных: {e}")
    else:
        a = "Good"
        #logging.info("База данных уязвимостей актуальна.")