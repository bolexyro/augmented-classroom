from sqlmodel import Session, select
from .models import Student, StudentPydanticModel, StudentUpdateModel
from sqlalchemy.exc import NoResultFound
from typing import Optional


def create_student(session: Session, student: StudentPydanticModel) -> Student | None:
    from .utils import get_password_hash
    student.password = get_password_hash(student.password)
    student.matric_number = student.matric_number.upper()
    db_student = Student.model_validate(student)
    if not session.get(Student, db_student.matric_number):
        session.add(db_student)
        session.commit()
        return db_student
    # if student already exists
    return None


# if you do StudentSQLModel | None in the annotation for what is meant to be returned, you would not get the editor support you should get
def get_student(session: Session, matric_number: str) -> Optional[Student]:
    try:
        matric_number = matric_number.upper()
        db_student = session.exec(select(Student).where(
            Student.matric_number == matric_number)).one()
        return db_student
    except NoResultFound:
        return None


def update_student(session: Session, matric_number: str, update_data: StudentUpdateModel):
    matric_number = matric_number.upper()
    db_student = session.exec(select(Student).where(
        Student.matric_number == matric_number)).one()
    update_dict = update_data.model_dump(exclude_unset=True)
    for column, value in update_dict.items():
        setattr(db_student, column, value)
    session.add(db_student)
    session.commit()
