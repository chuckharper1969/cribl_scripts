from typing import Optional
from uuid import UUID, uuid4
from pydantic import BaseModel
from enum import Enum

class Status(str, Enum):
    onboarding = "Onboarding"
    ok = "OK"
    error = "Error"

class Cluster(BaseModel):
    id: Optional[UUID] = uuid4()
    title: str
    description: Optional[str]
    username: str
    password: str
    url: str
    status: Status
    message: Optional[str]

class ClusterUpdate(BaseModel):
    title: str
    description: Optional[str]
    username: str
    password: str
    url: str
    status: Status
    message: Optional[str]