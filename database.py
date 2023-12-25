from sqlmodel import create_engine, SQLModel
import os
from dotenv import load_dotenv

load_dotenv(".env")

postgres_db_url = os.getenv("DB_URL")
# for some reason dude said to include this when working with fastapi
connect_args = {"check_same_thread": False}
sqlite_file_name = "students.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(url=sqlite_url, connect_args=connect_args)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


if __name__ == "__main__":
    create_db_and_tables()
