from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = 'Block IP addresses by adding them to the BlockedIP model'

    def add_arguments(self, parser):
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='One or more IP addresses to block'
        )
        parser.add_argument(
            '--reason',
            type=str,
            default='',
            help='Reason for blocking the IP(s)'
        )

    def handle(self, *args, **options):
        ip_addresses = options['ip_addresses']
        reason = options['reason']
        
        blocked_count = 0
        already_blocked_count = 0
        invalid_count = 0
        
        for ip_address in ip_addresses:
            try:
                # Validate IP address format
                validate_ipv46_address(ip_address)
                
                # Check if IP is already blocked
                blocked_ip, created = BlockedIP.objects.get_or_create(
                    ip_address=ip_address,
                    defaults={'reason': reason}
                )
                
                if created:
                    blocked_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'Successfully blocked IP: {ip_address}')
                    )
                else:
                    already_blocked_count += 1
                    self.stdout.write(
                        self.style.WARNING(f'IP already blocked: {ip_address}')
                    )
                    
            except ValidationError:
                invalid_count += 1
                self.stderr.write(
                    self.style.ERROR(f'Invalid IP address format: {ip_address}')
                )
            except Exception as e:
                invalid_count += 1
                self.stderr.write(
                    self.style.ERROR(f'Error blocking IP {ip_address}: {str(e)}')
                )
        
        # Summary
        self.stdout.write('\n--- Summary ---')
        self.stdout.write(f'IPs blocked: {blocked_count}')
        self.stdout.write(f'IPs already blocked: {already_blocked_count}')
        self.stdout.write(f'Invalid IPs: {invalid_count}')
        
        if blocked_count > 0:
            self.stdout.write(
                self.style.SUCCESS(f'\nSuccessfully processed {len(ip_addresses)} IP(s)')
            )
