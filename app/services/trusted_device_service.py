# ============================================================================
# FILE 3: backend/app/services/trusted_device_service.py
# ============================================================================

from datetime import datetime
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId


class TrustedDeviceService:
    """
    Service for managing trusted devices.
    """
    
    @staticmethod
    async def is_device_trusted(
        db: AsyncIOMotorDatabase,
        user_id: str,
        device_id: str
    ) -> bool:
        """
        Check if a device is in user's trusted devices.
        
        Parameters
        ----------
        db : AsyncIOMotorDatabase
            Database instance
        user_id : str
            User ID
        device_id : str
            Device ID to check
            
        Returns
        -------
        bool
            True if device is trusted and active, False otherwise
        """
        trusted_device = await db.trusted_devices.find_one({
            "user_id": user_id,
            "device_id": device_id,
            "is_active": True
        })
        return trusted_device is not None
    
    @staticmethod
    async def trust_device(
        db: AsyncIOMotorDatabase,
        user_id: str,
        device_id: str,
        device_name: str,
        device_info: dict,
        ip_address: str,
        location: dict
    ) -> str:
        """
        Add a device to user's trusted devices.
        
        Parameters
        ----------
        db : AsyncIOMotorDatabase
            Database instance
        user_id : str
            User ID
        device_id : str
            Device ID to trust
        device_name : str
            Human-readable device name
        device_info : dict
            Full device information
        ip_address : str
            IP address when device was trusted
        location : dict
            Location when device was trusted
            
        Returns
        -------
        str
            ID of created trusted device record
        """
        # Check if device already exists (might have been revoked)
        existing = await db.trusted_devices.find_one({
            "user_id": user_id,
            "device_id": device_id
        })
        
        now = datetime.utcnow()
        
        if existing:
            # Reactivate if it was revoked
            await db.trusted_devices.update_one(
                {"_id": existing["_id"]},
                {
                    "$set": {
                        "is_active": True,
                        "trusted_at": now,
                        "last_used": now,
                        "ip_address": ip_address,
                        "location": location,
                        "revoked_at": None
                    }
                }
            )
            return str(existing["_id"])
        else:
            # Create new trusted device
            trusted_device = {
                "user_id": user_id,
                "device_id": device_id,
                "device_name": device_name,
                "device_info": device_info,
                "trusted_at": now,
                "first_used": now,
                "last_used": now,
                "ip_address": ip_address,
                "location": location,
                "is_active": True,
                "revoked_at": None
            }
            
            result = await db.trusted_devices.insert_one(trusted_device)
            return str(result.inserted_id)
    
    @staticmethod
    async def update_last_used(
        db: AsyncIOMotorDatabase,
        user_id: str,
        device_id: str
    ) -> None:
        """
        Update last_used timestamp for a trusted device.
        
        Parameters
        ----------
        db : AsyncIOMotorDatabase
            Database instance
        user_id : str
            User ID
        device_id : str
            Device ID
        """
        await db.trusted_devices.update_one(
            {
                "user_id": user_id,
                "device_id": device_id,
                "is_active": True
            },
            {"$set": {"last_used": datetime.utcnow()}}
        )
    
    @staticmethod
    async def get_trusted_devices(
        db: AsyncIOMotorDatabase,
        user_id: str,
        active_only: bool = True
    ) -> list:
        """
        Get all trusted devices for a user.
        
        Parameters
        ----------
        db : AsyncIOMotorDatabase
            Database instance
        user_id : str
            User ID
        active_only : bool
            If True, return only active devices
            
        Returns
        -------
        list
            List of trusted device documents
        """
        query = {"user_id": user_id}
        if active_only:
            query["is_active"] = True
        
        cursor = db.trusted_devices.find(query).sort("last_used", -1)
        return await cursor.to_list(length=None)
    
    @staticmethod
    async def revoke_device(
        db: AsyncIOMotorDatabase,
        user_id: str,
        device_id: str
    ) -> bool:
        """
        Revoke a trusted device.
        
        Parameters
        ----------
        db : AsyncIOMotorDatabase
            Database instance
        user_id : str
            User ID
        device_id : str
            Device ID to revoke
            
        Returns
        -------
        bool
            True if device was revoked, False if not found
        """
        result = await db.trusted_devices.update_one(
            {
                "user_id": user_id,
                "device_id": device_id,
                "is_active": True
            },
            {
                "$set": {
                    "is_active": False,
                    "revoked_at": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    @staticmethod
    async def get_device_by_id(
        db: AsyncIOMotorDatabase,
        device_id: str
    ) -> Optional[dict]:
        """
        Get a trusted device by its MongoDB ID.
        
        Parameters
        ----------
        db : AsyncIOMotorDatabase
            Database instance
        device_id : str
            MongoDB _id of the trusted device
            
        Returns
        -------
        Optional[dict]
            Trusted device document or None
        """
        try:
            return await db.trusted_devices.find_one({"_id": ObjectId(device_id)})
        except:
            return None
