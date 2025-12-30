# app/schemas/transaction_schema.py

from pydantic import BaseModel

class TransactionCreate(BaseModel):
    amount: float
    category: str  
    description: str

