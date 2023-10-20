from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import psycopg2
import os
from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv(".env")

db = os.getenv("DB_NAME")
db_username = os.getenv("DB_USERNAME")
db_password = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_INTERNAL_HOST")
db_port = os.getenv("DB_PORT")

connection_params = {"database": db,
                     "user": db_username,
                     "host": db_host,
                     "password": db_password,
                     "port": db_port}

app = FastAPI()


class Student(BaseModel):
    matric_number: str
    password: str


@app.get(path="/")
def home():
    return True


@app.post(path="/create-user")
def create_user(student: Student):
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table = "SELECT matric_number, password FROM students WHERE matric_number = %s"
            cursor.execute(select_user_info_from_students_table,
                           (student.matric_number, ))
            result = cursor.fetchone()
            if not result:
                insert_new_student_info_into_students_table_sql = "INSERT INTO students(matric_number, password) VALUES (%s, %s)"
                cursor.execute(insert_new_student_info_into_students_table_sql,
                               (student.matric_number, student.password))
                connection.commit()
                response_data = {"message": "Student created."}
                return JSONResponse(status_code=200, content=response_data)
            return JSONResponse(status_code=400, content={"message": "Student already exists."})


@app.get(path="/verify-user")
def get_user(username: str, password: str):
    with psycopg2.connect(**connection_params) as connection:
        with connection.cursor() as cursor:
            select_user_info_from_students_table = "SELECT matric_number, password FROM students WHERE matric_number = %s"
            cursor.execute(select_user_info_from_students_table, (username, ))
            result = cursor.fetchone()
            if not result:
                response_data = {"message": "matric_number not found."}
                return JSONResponse(status_code=404, content=response_data)
            retrieved_username, retrieved_password = result
            if retrieved_password != password:
                response_data = {"Incorrect password."}
                return JSONResponse(status_code=401, content=response_data)
            return JSONResponse(status_code=200, content={"message": "Login successful."})


uvicorn.run(app=app, host="0.0.0.0")
