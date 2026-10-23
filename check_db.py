from app.database import get_db

db = get_db()

query = """
SELECT name
FROM sqlite_master
WHERE type = 'table'
ORDER BY name
"""

tables = [row["name"] for row in db.execute(query)]

print("Database tables:")
for table in tables:
    print("-", table)

db.close()
