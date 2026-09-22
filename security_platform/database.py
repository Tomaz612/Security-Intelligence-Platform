import os
import psycopg
from psycopg.types.json import Jsonb
from dotenv import load_dotenv



load_dotenv()


def get_connection():
    return psycopg.connect(
        host=os.getenv("DATABASE_HOST"),
        dbname=os.getenv("DATABASE_NAME"),
        user=os.getenv("DATABASE_USER"),
        password=os.getenv("DATABASE_PASSWORD")
    )

def save_scan(target, risk_score, risk_level, scan_results):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO scans (
                    target,
                    risk_score,
                    risk_level,
                    scan_results
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    target,
                    risk_score,
                    risk_level,
                    Jsonb(scan_results)
                )
            )

        connection.commit()

    finally:
        connection.close()