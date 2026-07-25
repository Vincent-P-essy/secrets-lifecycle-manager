"""slm - secret rotation as a state machine with an overlap window.

Create, promote, verify, revoke. The old version is not revoked until consumers
are shown to have migrated, because rotation without revocation only increases
the number of live credentials.
"""

__version__ = "1.0.0"
