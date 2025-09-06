import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP


logger = logging.getLogger(__name__)


class IPLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, and path of every incoming request.
    Also blocks requests from blacklisted IPs.
    """

    def process_request(self, request):
        """
        Process incoming request, check for blocked IPs, and log request details.
        """
        # Get client IP address
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from IP: {ip_address}")
            return HttpResponseForbidden("Access denied: Your IP address has been blocked.")
        
        # Get the requested path
        path = request.get_full_path()
        
        try:
            # Create and save the request log
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path
            )
            
            logger.info(f"Request logged: {ip_address} - {path}")
            
        except Exception as e:
            # Log error but don't break the request flow
            logger.error(f"Failed to log request: {e}")
        
        return None

    def is_ip_blocked(self, ip_address):
        """
        Check if the given IP address is in the blocked list.
        """
        try:
            return BlockedIP.objects.filter(ip_address=ip_address).exists()
        except Exception as e:
            logger.error(f"Error checking blocked IP: {e}")
            return False

    def get_client_ip(self, request):
        """
        Get the client's IP address from request headers.
        Handles cases where the request is behind a proxy or load balancer.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get the first IP in the chain (the original client)
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            # Fallback to REMOTE_ADDR
            ip = request.META.get('REMOTE_ADDR')
        
        return ip
