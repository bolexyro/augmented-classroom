import psycopg2
import os
from dotenv import load_dotenv

load_dotenv(".env")
db = os.getenv("DB_NAME")
db_username = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT")

conn = psycopg2.connect(database=db,
                        user=db_username,
                        host=db_host,
                        password=db_password,
                        port=db_port)

# SQL statement to create the table
create_table_sql = """
CREATE TABLE student(
matric_number VARCHAR(15) PRIMARY KEY,
password TEXT,
credential_id bytea,
public_key bytea,
sign_count INTEGER,
user_id UUID,
transports TEXT,
registration_challenge bytea,
authentication_challenge bytea
)
"""


cursor = conn.cursor()
cursor.execute(create_table_sql)

# Commit the transaction
conn.commit()

print("Table 'student' created successfully.")
cursor.close()
conn.close()
