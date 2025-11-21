"""
Database Schemas for Asset Management System

Each Pydantic model below represents a MongoDB collection. The collection
name is the lowercase of the class name (handled by the Flames platform).

- User -> "user"
- Asset -> "asset"
- Assignment -> "assignment"
- Maintenance -> "maintenance"
- Requisition -> "requisition"
- InventoryThreshold -> "inventorythreshold"
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import date, datetime


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email")
    role: Literal["admin", "manager", "staff"] = Field(
        "staff", description="Access role determining permissions"
    )
    is_active: bool = Field(True, description="Whether user is active")
    # Password is not stored here for schema browser; hashed password is stored in DB only.


class AssetDocument(BaseModel):
    filename: str
    url: str
    uploaded_at: datetime
    category: Optional[Literal["purchase", "warranty", "other"]] = "other"


class Asset(BaseModel):
    asset_id: str = Field(..., description="Unique asset identifier or tag")
    name: str
    type: str
    serial_number: Optional[str] = None
    purchase_date: Optional[date] = None
    supplier_name: Optional[str] = None
    warranty_period_months: Optional[int] = Field(
        None, ge=0, description="Warranty period in months"
    )
    status: Literal["available", "assigned", "maintenance", "retired"] = "available"
    documents: List[AssetDocument] = []


class Assignment(BaseModel):
    asset_id: str
    assignee_type: Literal["department", "customer", "office"]
    assignee_name: str
    issue_date: date
    responsible_person: Optional[str] = None
    designation: Optional[str] = None
    notes: Optional[str] = None
    active: bool = True


class Maintenance(BaseModel):
    asset_id: str
    service_date: date
    service_type: Literal["scheduled", "repair", "inspection"] = "scheduled"
    cost: Optional[float] = Field(None, ge=0)
    notes: Optional[str] = None
    next_service_date: Optional[date] = None


class InventoryThreshold(BaseModel):
    item_name: str
    current_level: int = Field(0, ge=0)
    min_level: int = Field(0, ge=0)
    unit: Optional[str] = "units"


class Requisition(BaseModel):
    item_name: str
    requested_by: str
    quantity: int = Field(..., ge=1)
    reason: Optional[str] = None
    status: Literal["open", "approved", "rejected", "ordered"] = "open"
