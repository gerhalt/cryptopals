"""General-purpose helper functions.

This module contains useful functions that aren't associated with any
specific challenge.
"""


def bytes_to_str(inp: bytes) -> str:
    """Converts a bytes object to a clean printable hexademical string, e.g.:

    bytes_to_str(bytes([0x12, 0x13, 0x14])) -> "121314"
    """
    return ''.join([f'{b:02x}' for b in inp])
