from django.contrib import admin

from .models import PasswordHistory


@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    """Admin view for stored SHA-256 password history.

    We never expose plaintext — only hashes, score, and metadata.
    """

    list_display = (
        "session_key",
        "strength_label",
        "strength_score",
        "length",
        "created_at",
    )
    list_filter = ("strength_label",)
    search_fields = ("session_key", "password_hash")
    readonly_fields = (
        "session_key",
        "user_id",
        "password_hash",
        "strength_score",
        "strength_label",
        "length",
        "created_at",
    )

    def has_add_permission(self, request):
        # Disallow manual creation — only the analyzer view writes here.
        return False
