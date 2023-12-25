from sqlmodel import Session, select
from models import StudentSQLModel, StudentPydanticModel, StudentUpdateModel
from utils import get_password_hash
from sqlalchemy.exc import NoResultFound
from typing import Optional


def create_student(session: Session, student: StudentPydanticModel) -> StudentSQLModel | None:
    student.password = get_password_hash(student.password)
    student.matric_number = db_student.matric_number.upper()
    db_student = StudentSQLModel.model_validate(student)
    if not session.get(StudentSQLModel, db_student.matric_number):
        session.add(db_student)
        session.commit()
        return student
    # if student already exists
    return None


# it is meant to
# if you do StudentSQLModel, you would not get the editor support you should get
def get_student(session: Session, matric_number: str) -> Optional[StudentSQLModel]:
    try:
        db_student = session.exec(select(StudentSQLModel).where(
            StudentSQLModel.matric_number == matric_number)).one()
        return db_student
    except NoResultFound:
        return None


def update_student(session: Session, matric_number: str, update_data: StudentUpdateModel):
    db_student = session.exec(select(StudentSQLModel).where(
        StudentSQLModel.matric_number == matric_number)).one()
    update_dict = update_data.model_dump(exclude_unset=True)
    for column, value in update_dict.items():
        setattr(db_student, column, value)
    session.add(db_student)
    session.commit()
