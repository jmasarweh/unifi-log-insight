"""
IANA Service Name Lookup

Maps port numbers and transport protocols to IANA-registered service names.
CSV source: https://www.iana.org/assignments/service-names-port-numbers/

The CSV is bundled at build time in receiver/data/ and copied to /app/data/ by Docker.
"""
import csv
import logging
from pathlib import Path
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)

# Global service mapping: (port, protocol) -> service_name
_SERVICE_MAP: Dict[Tuple[int, str], str] = {}

def _load_service_map() -> Dict[Tuple[int, str], str]:
    """
    Load IANA service names from CSV at module initialization.

    Returns dict keyed by (port, protocol) -> service_name.
    Gracefully degrades to empty dict if CSV is missing or malformed.
    """
    service_map = {}
    csv_path = Path(__file__).parent / 'data' / 'service-names-port-numbers.csv'

    if not csv_path.exists():
        logger.warning(f"IANA service CSV not found at {csv_path} — service name lookups will return None")
        return service_map

    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Extract fields
                service_name = row.get('Service Name', '').strip()
                description = row.get('Description', '').strip()
                port_str = row.get('Port Number', '').strip()
                protocol = row.get('Transport Protocol', '').strip().lower()
                reference = row.get('Reference', '').strip()

                # Use description if available, otherwise fall back to service name
                # Description is more user-friendly (e.g., "Message Submission over TLS protocol" vs "submissions")
                display_name = description or service_name

                # Skip entries without a name or port
                if not display_name or not port_str:
                    continue

                # Parse port number (can be a range like "80-90", we take first)
                try:
                    # Handle port ranges by taking the first port
                    if '-' in port_str:
                        port = int(port_str.split('-')[0])
                    else:
                        port = int(port_str)
                except ValueError:
                    continue

                # Skip invalid protocols
                if protocol not in ('tcp', 'udp', 'sctp', 'dccp'):
                    continue

                # Prefer RFC-standardized entries over non-standard ones
                # If we already have an entry, only replace it if the new one has an RFC reference
                key = (port, protocol)
                if key not in service_map:
                    service_map[key] = display_name
                elif reference and 'RFC' in reference.upper():
                    # Replace existing entry if this one has RFC backing (more authoritative)
                    service_map[key] = display_name

        logger.info(f"Loaded {len(service_map)} IANA service name mappings from {csv_path}")

    except Exception as e:
        logger.error(
            f"Failed to parse IANA service CSV at {csv_path}: {e} — "
            f"returning {len(service_map)} entries parsed before error"
        )
        return service_map

    return service_map

# Initialize at module load
_SERVICE_MAP = _load_service_map()

def get_service_mappings() -> Dict[Tuple[int, str], str]:
    """Return the full service mapping dictionary.

    Returns:
        Dict keyed by (port, protocol) -> service_name.
    """
    return _SERVICE_MAP

def get_service_name(port: Optional[int], protocol: Optional[str] = 'tcp') -> Optional[str]:
    """
    Return IANA service name for the given port and protocol.

    Args:
        port: Port number (e.g., 80, 443). Can be None for non-port protocols like ICMP.
        protocol: Transport protocol ('TCP', 'UDP', etc.). Case-insensitive. Defaults to 'tcp'.

    Returns:
        Service name string if found, otherwise None.

    Examples:
        >>> get_service_name(80, 'TCP')
        'http'
        >>> get_service_name(443, 'tcp')
        'https'
        >>> get_service_name(53, 'udp')
        'domain'
        >>> get_service_name(None, 'icmp')
        None
    """
    if port is None:
        return None

    # Normalize protocol to lowercase (parsers.py extracts as uppercase from iptables)
    normalized_protocol = (protocol or 'tcp').lower()

    return _SERVICE_MAP.get((port, normalized_protocol))
