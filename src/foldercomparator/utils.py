import math
import time
import hashlib
import datetime

def calculate_hash(file_path, hash_algorithm='md5', block_size=65536):
    """Calculates the hash of a file using the specified algorithm (md5 or sha256)."""
    if hash_algorithm == 'md5':
        hasher = hashlib.md5()
    elif hash_algorithm == 'sha256':
        hasher = hashlib.sha256()
    else:
        return None # Should not happen with argparse choices

    try:
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Failure to calculate hash {e=}")


def format_size_human_readable(size_in_bytes):
    """
    Convertit une taille en octets en une chaîne de caractères lisible par un humain
    (Bytes, KB, MB, GB, TB, etc.).
    # --- Exemples d'utilisation ---
    # print(format_size_human_readable(0))                   # 0    Bytes
    # print(format_size_human_readable(100))                 # 100  Bytes
    # print(format_size_human_readable(1023))                # 1023 Bytes
    # print(format_size_human_readable(1024))                # 1.0  KB
    # print(format_size_human_readable(1500))                # 1.46 KB
    # print(format_size_human_readable(1024 * 1024))         # 1.0  MB
    # print(format_size_human_readable(5 * (1024**3)))       # 5.0  GB
    # print(format_size_human_readable(2.5 * (1024**4)))     # 2.5  TB
    # print(format_size_human_readable(1234567890))          # 1.15 GB
    # print(format_size_human_readable(9876543210987654321)) # 8.59 EB (Exabytes)

    """
    if size_in_bytes < 0:
        PM=-1.
        size_in_bytes = size_in_bytes * PM
    else:
        PM=1.
    if size_in_bytes == 0:
        return "0 Bytes"

    # List of units : Bytes, Kilobytes, Megabytes, Gigabytes, Terabytes, Petabytes, etc.
    units = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']

    # Calculates the index of the appropriate unit
    # Ex: for 1024 Bytes, log base 1024 of 1024 is 1, so KB (index 1)
    # For 1023 Bytes, log base 1024 of 1023 is 0.99..., floor gives 0, so Bytes (index 0)
    i = int(math.floor(math.log(size_in_bytes, 1024)))

    # Ensure that the index does not exceed the number of units available
    if i >= len(units):
        i = len(units) - 1 # Use the largest unit available

    # Calculates the value in the chosen unit
    power = 1024 ** i
    formatted_value = PM*round(size_in_bytes / power, 2) # Rounded to 2 decimal places
    size_in_bytes = size_in_bytes * PM

    return f"{formatted_value} {units[i]}"


def get_formatted_dates():
    """
    Generates and returns formatted local and UTC date strings.

    Returns:
        tuple: A tuple containing (local_date_str, utc_date_str).
    """
    now_local = datetime.datetime.now()
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    # Calculate UTC offset for local time
    utc_offset_seconds = time.altzone if time.daylight else time.timezone
    utc_offset_hours = -utc_offset_seconds / 3600.0

    if utc_offset_hours == int(utc_offset_hours):
        local_offset_str = f"UTC{'+' if utc_offset_hours >= 0 else ''}{int(utc_offset_hours)}"
    else:
        sign = '+' if utc_offset_hours >= 0 else ''
        hours = int(abs(utc_offset_hours))
        minutes = int((abs(utc_offset_hours) - hours) * 60)
        local_offset_str = f"UTC{sign}{hours:02d}:{minutes:02d}"

    local_date_str = now_local.strftime(f"%a %b %d %H:%M:%S {local_offset_str} %Y")
    utc_date_str = now_utc.strftime("%a %b %d %H:%M:%S UTC %Y")

    return local_date_str, utc_date_str