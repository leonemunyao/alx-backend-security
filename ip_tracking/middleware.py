import logging
import requests
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP


logger = logging.getLogger(__name__)


class IPLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, path, and geolocation of every incoming request.
    Also blocks requests from blacklisted IPs.
    """

    def process_request(self, request):
        """
        Process incoming request, check for blocked IPs, get geolocation, and log request details.
        """
        # Get client IP address
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            logger.warning(f"Blocked request from IP: {ip_address}")
            return HttpResponseForbidden("Access denied: Your IP address has been blocked.")
        
        # Get the requested path
        path = request.get_full_path()
        
        # Get geolocation data (with 24-hour caching)
        country, city = self.get_geolocation(ip_address)
        
        try:
            # Create and save the request log with geolocation data
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                country=country,
                city=city
            )
            
            location_str = f"{city}, {country}" if city != "Unknown" or country != "Unknown" else "Unknown Location"
            logger.info(f"Request logged: {ip_address} - {path} - {location_str}")
            
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

    def get_geolocation(self, ip_address):
        """
        Get geolocation data for the given IP address.
        Uses caching to store results for 24 hours.
        """
        # Skip geolocation for local/private IPs
        if self.is_private_ip(ip_address):
            return "Local", "Local"
        
        # Check cache first (24 hours)
        cache_key = f"geo_{ip_address}"
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.debug(f"Cache hit for IP {ip_address}: {cached_result}")
            return cached_result
        
        try:
            # Use ip-api.com for geolocation (free tier)
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}?fields=status,country,city",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('country', 'Unknown')
                    city = data.get('city', 'Unknown')
                    
                    # Cache the result for 24 hours (86400 seconds)
                    cache.set(cache_key, (country, city), 86400)
                    logger.info(f"Cached geolocation for IP {ip_address}: {city}, {country}")
                    return country, city
                else:
                    logger.warning(f"API returned failure status for IP {ip_address}")
                    
        except requests.Timeout:
            logger.warning(f"Geolocation API timeout for IP {ip_address}")
        except requests.RequestException as e:
            logger.error(f"Geolocation API error for IP {ip_address}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error getting geolocation for IP {ip_address}: {e}")
        
        # Return default values if API fails
        return "Unknown", "Unknown"

    def is_private_ip(self, ip_address):
        """
        Check if the IP address is a private/local IP.
        """
        if not ip_address:
            return True
        
        # Common private IP ranges and localhost
        private_ranges = [
            '127.',      # localhost
            '10.',       # Class A private
            '192.168.',  # Class C private
            '172.16.',   # Class B private start
            '172.17.', '172.18.', '172.19.', '172.20.',
            '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.',
            '172.29.', '172.30.', '172.31.',  # Class B private end
            '169.254.',  # Link-local
        ]
        
        return any(ip_address.startswith(prefix) for prefix in private_ranges)

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
