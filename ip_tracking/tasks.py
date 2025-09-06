from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from datetime import timedelta
import logging
from .models import RequestLog, SuspiciousIP

logger = logging.getLogger(__name__)


@shared_task
def detect_anomalies():
    """
    Celery task to detect anomalous IP behavior.
    Runs hourly to flag suspicious IPs based on:
    1. IPs exceeding 100 requests/hour
    2. IPs accessing sensitive paths (/admin, /login)
    """
    logger.info("Starting anomaly detection task...")
    
    # Get the time window (last hour)
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    
    # Detection 1: IPs exceeding 100 requests/hour
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago, timestamp__lt=now)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        SuspiciousIP.objects.create(
            ip_address=ip_address,
            reason=f'High volume activity: {request_count} requests in 1 hour'
        )
        logger.warning(f"Flagged high volume IP: {ip_address} ({request_count} requests)")
    
    # Detection 2: IPs accessing sensitive paths
    sensitive_paths = ['/admin', '/login']
    
    for sensitive_path in sensitive_paths:
        sensitive_access_ips = (
            RequestLog.objects
            .filter(
                timestamp__gte=one_hour_ago,
                timestamp__lt=now,
                path__startswith=sensitive_path
            )
            .values('ip_address')
            .annotate(access_count=Count('id'))
            .filter(access_count__gte=5)
        )
        
        for ip_data in sensitive_access_ips:
            ip_address = ip_data['ip_address']
            access_count = ip_data['access_count']
            
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'Sensitive path access: {sensitive_path} ({access_count} times)'
            )
            logger.warning(f"Flagged sensitive path access: {ip_address} -> {sensitive_path}")
    
    logger.info("Anomaly detection completed.")
    return "Anomaly detection completed."
