"""Business-logic layer that mediates between the API and the cache tier."""
import logging
import time

from redis_command_relay import RedisCommandRelay

logger = logging.getLogger(__name__)


class ProfileUpdate:
    """Small DTO bundling a profile field change with a request timestamp."""

    def __init__(self, user_id: str, field: str, value: str):
        self.user_id = user_id
        self.field = field
        self.value = value
        self.requested_at = time.time()


class ProfileService:
    """Coordinates profile writes and pushes them into the shared cache."""

    def __init__(self):
        self._relay = RedisCommandRelay(host="cache.internal", port=6379)

    def update_display_name(self, user_id: str, display_name: str):
        update = ProfileUpdate(user_id=user_id, field="display_name", value=display_name)
        logger.info(
            "profile update requested for user %s at %.0f",
            update.user_id, update.requested_at,
        )
        self._relay.write_profile_field(update)
