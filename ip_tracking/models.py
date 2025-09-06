from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """
    Model to store request logs including IP address, timestamp, path, and geolocation data.
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
    country = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Country from which the request originated"
    )
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="City from which the request originated"
    )

    class Meta:
        db_table = 'ip_tracking_requestlog'
        ordering = ['-timestamp']
        verbose_name = 'Request Log'
        verbose_name_plural = 'Request Logs'

    def __str__(self):
        location = f"{self.city}, {self.country}" if self.city and self.country else "Unknown Location"
        return f"{self.ip_address} - {self.path} - {location} - {self.timestamp}"


class BlockedIP(models.Model):
    """
    Model to store blocked IP addresses.
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        help_text="IP address to be blocked"
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the IP was blocked"
    )
    reason = models.CharField(
        max_length=255,
        blank=True,
        help_text="Reason for blocking this IP"
    )

    class Meta:
        db_table = 'ip_tracking_blockedip'
        ordering = ['-created_at']
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'

    def __str__(self):
        return f"Blocked: {self.ip_address}"


class SuspiciousIP(models.Model):
    """
    Model to store suspicious IP addresses flagged by anomaly detection.
    """
    ip_address = models.GenericIPAddressField(
        help_text="IP address flagged as suspicious"
    )
    reason = models.CharField(
        max_length=255,
        help_text="Reason why this IP was flagged as suspicious"
    )

    class Meta:
        db_table = 'ip_tracking_suspiciousip'
        ordering = ['-id']
        verbose_name = 'Suspicious IP'
        verbose_name_plural = 'Suspicious IPs'

    def __str__(self):
        return f"Suspicious: {self.ip_address} - {self.reason}"
