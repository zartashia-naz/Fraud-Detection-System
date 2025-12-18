from typing import Optional
from pydantic import BaseModel, EmailStr

class User(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    cnic: str
    password: str  # hashed password
