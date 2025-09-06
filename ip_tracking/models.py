from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """
    Model to store request logs including IP address, timestamp, and path.
    """
    ip_address = models.GenericIPAddressField(
        help_text="IP address of the client making the request"
    )
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="When the request was made"
    )
    path = models.CharField(
        max_length=500,
        help_text="The URL path that was requested"
    )

    class Meta:
        db_table = 'ip_tracking_requestlog'
        ordering = ['-timestamp']
        verbose_name = 'Request Log'
        verbose_name_plural = 'Request Logs'

    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"
