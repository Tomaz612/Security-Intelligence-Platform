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
    
def get_previous_scan(target):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, target, scanned_at, risk_score, risk_level, scan_results
                FROM scans
                WHERE target = %s
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (target,)
            )

            row = cursor.fetchone()

            if row is None:
                return None

            return {
                "id": row[0],
                "target": row[1],
                "scanned_at": row[2],
                "risk_score": row[3],
                "risk_level": row[4],
                "scan_results": row[5]
            }
        
    finally:
        connection.close()



def get_scan_history(target):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    target,
                    scanned_at,
                    risk_score,
                    risk_level,
                    scan_results
                FROM scans
                WHERE target = %s
                ORDER BY scanned_at DESC
                """,
                (target,)
            )

            rows = cursor.fetchall()

            return [
                {
                    "id": row[0],
                    "target": row[1],
                    "scanned_at": row[2],
                    "risk_score": row[3],
                    "risk_level": row[4],
                    "scan_results": row[5]
                }
                for row in rows
            ]

    finally:
        connection.close()