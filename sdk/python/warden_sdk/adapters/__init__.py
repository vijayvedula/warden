"""Identity adapters: native platform identity -> canonical Warden claims.

Each adapter is pure data mapping and never signs authority itself.
"""

from . import aws, azure, databricks, google
from .base import IdentityAdapter

__all__ = ["aws", "azure", "databricks", "google", "IdentityAdapter"]
