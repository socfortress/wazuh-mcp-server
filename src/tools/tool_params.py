from pydantic import BaseModel, Field
from typing import Optional, List

class AuthenticateArgs(BaseModel):
    pass  # No parameters needed for single cluster

class GetAgentsArgs(BaseModel):
    status : Optional[List[str]] = Field(None, examples=[["active","pending"]])
    limit  : Optional[int] = 500
    offset : Optional[int] = 0