# app/api/v1/routes/test_db_route.py
from fastapi import APIRouter, Depends
from app.db.mongodb import get_database

router = APIRouter(
    prefix="/test",
    tags=["Test"]
)

@router.get("/mongo")
async def test_mongo(db=Depends(get_database)):
    try:
        # Motor async method — must await
        collections = await db.list_collection_names()

        return {
            "status": "success",
            "message": "Connected to MongoDB!",
            "collections": collections
        }

    except Exception as e:
        return {
            "status": "failed",
            "error": str(e)
        }

