import hashlib

from django.db import models
from django.utils import timezone


class PasswordHistory(models.Model):
    """Stores SHA-256 hashes of previously analyzed passwords.

    Privacy contract:
    - We never persist plaintext passwords.
    - The hash is deterministic so that "have I seen this password before?"
      is a constant-time lookup via `password_hash`.
    - Rows are scoped by `session_key`; `user_id` is reserved for future
      authenticated use.
    """

    session_key = models.CharField(max_length=64, db_index=True)
    user_id = models.IntegerField(null=True, blank=True, db_index=True)
    password_hash = models.CharField(max_length=64, unique=True)
    strength_score = models.IntegerField()
    strength_label = models.CharField(max_length=16)
    length = models.IntegerField()
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["session_key", "-created_at"]),
        ]

    @staticmethod
    def hash_password(raw: str) -> str:
        """Return the SHA-256 hex digest of a UTF-8 password string."""
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def __str__(self) -> str:
        return (
            f"{self.session_key[:8]}… {self.strength_label} "
            f"({self.strength_score}) @ {self.created_at:%Y-%m-%d %H:%M}"
        )
