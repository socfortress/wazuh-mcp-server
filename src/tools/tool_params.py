from pydantic import BaseModel, Field
from typing import Optional, List

class AuthenticateArgs(BaseModel):
    pass

class GetAgentsArgs(BaseModel):
    status: Optional[List[str]] = Field(None, examples=[["active"]])
    limit : Optional[int] = 500
    offset: Optional[int] = 0