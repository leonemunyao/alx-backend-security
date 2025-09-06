import logging
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog


logger = logging.getLogger(__name__)


class IPLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, and path of every incoming request.
    """

    def process_request(self, request):
        """
        Process incoming request and log IP, timestamp, and path.
        """
        # Get client IP address
        ip_address = self.get_client_ip(request)
        
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
