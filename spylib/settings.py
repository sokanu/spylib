"""Settings file for spylib config."""
from __future__ import absolute_import
import os


AUTH_BASE_URL = os.environ.get("SPYLIB_AUTH_BASE_URL", "https://auth.localhost:8000")
