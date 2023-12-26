from sqlmodel import create_engine, SQLModel
import os
from dotenv import load_dotenv

load_dotenv(".env")

postgres_db_url = os.getenv("DB_URL")
engine = create_engine(url=postgres_db_url)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


if __name__ == "__main__":
    create_db_and_tables()
