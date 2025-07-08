from pydantic import BaseModel, Field
from typing import Optional, List

class AuthenticateArgs(BaseModel):
    cluster: str = Field(..., description="Cluster name from clusters.yml")

class GetAgentsArgs(BaseModel):
    cluster: str
    status : Optional[List[str]] = Field(None, examples=[["active","pending"]])
    limit  : Optional[int] = 500
    offset : Optional[int] = 0