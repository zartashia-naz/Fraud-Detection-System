# app/db/models/detection_rule_model.py
"""
DetectionRule Model for custom fraud detection rules.

Allows admins to create and manage custom detection rules.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class RuleType(str, Enum):
    ML = "ml"
    RULE = "rule"
    HYBRID = "hybrid"


class RuleAction(str, Enum):
    FLAG = "flag"
    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"


class DetectionRule(BaseModel):
    """Detection rule model for MongoDB storage"""

    name: str
    description: str
    type: RuleType = RuleType.RULE
    enabled: bool = True

    # Rule conditions
    conditions: Dict[str, Any] = Field(default_factory=dict)
    # Example conditions:
    # {
    #     "field": "amount",
    #     "operator": "greater_than",
    #     "value": 10000,
    #     "and": [
    #         {"field": "is_new_device", "operator": "equals", "value": true}
    #     ]
    # }

    # Thresholds
    threshold: float = Field(ge=0, le=100, default=50.0)

    # Action to take when rule triggers
    action: RuleAction = RuleAction.FLAG

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None  # admin_id
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0

    # Tags for categorization
    tags: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True
        json_schema_extra = {
            "example": {
                "name": "High Value Transaction Alert",
                "description": "Flag transactions over $10,000 from new devices",
                "type": "rule",
                "enabled": True,
                "conditions": {
                    "field": "amount",
                    "operator": "greater_than",
                    "value": 10000,
                },
                "threshold": 70.0,
                "action": "flag",
                "tags": ["high_value", "new_device"],
            }
        }


class DetectionRuleInDB(DetectionRule):
    """Detection rule model with MongoDB _id"""

    id: Optional[str] = Field(None, alias="_id")

    class Config:
        populate_by_name = True
