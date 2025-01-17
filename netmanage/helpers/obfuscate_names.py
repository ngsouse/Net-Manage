#!/usr/bin/env python3
"""
Database Obfuscation and Reversal Module.

This module provides functionality to obfuscate and reverse data in SQLite
databases. It uses a pre-defined mapping of columns to apply specific
transformations based on the column's semantic role. The module uses random
character mapping to obfuscate string data. This ensures referential integrity
while making it visually obscured for demonstrations.

Functions:
    - random_map_transform: Transform a string using a forward mapping.
    - reverse_map_transform: Transform a string using a reverse mapping.
    - consistent_transform: Obfuscate a string based on predefined rules.
    - copy_table_structure: Copies the schema of a table from one SQLite
        database to another.
    - reverse_consistent_transform: Reverse the obfuscation based on
        predefined rules.
    - obfuscate_db_data: Obfuscate an SQLite database.
    - reverse_db_data: Reverse the obfuscation on an SQLite database.

Example:
    >>> obfuscate_db_data("input.db", "output_obfuscated.db")
    >>> reverse_db_data("output_obfuscated.db", "output_reversed.db")
"""

import sqlite3
import re
import string
import random
from pathlib import Path
from netmanage.helpers.obfuscate_addresses import transform_ip


def get_columns_to_rename():
    # Define a dictionary that sets rules for renaming columns
    # Keys are column names
    # values are dictionaries that specify 'ignores' and 'prefix'
    return {
        'device': {
            'ignores': ['switch', 'sw', 'rtr', 'router', 'fw', 'firewall',
                        'local'],
            'prefix': 'dev-'},
        'Vlan': {'ignores': ['routed', 'trunk'], 'prefix': 'Vlan-'},
        'vlan': {'ignores': ['routed', 'trunk'], 'prefix': 'vlan-'},
        'nameif': {
            'ignores': ['management', 'inside', 'outside', 'link', 'dmz',
                        'pci', 'ext', 'mgt', 'mgmt', 'int', 'vpn'],
            'prefix': 'iface-'},
        'description': {
            'ignores': ['sw', 'switch', 'rtr', 'router'], 'prefix': 'desc-'},
        'notes': {'ignores': ['sw', 'switch', 'rtr', 'router'],
                  'prefix': 'note-'},
        'desc': {'ignores': ['sw', 'switch', 'rtr', 'router'],
                 'prefix': 'dsc-'},
        'partition': {'ignores': [], 'prefix': 'part-'},
        'node': {'ignores': [], 'prefix': 'node-'},
        'name': {'ignores': [], 'prefix': 'name-'},
        'pool': {'ignores': ['Server', 'srvr', 'svr'], 'prefix': 'pool-'},
        'pool_name': {'ignores': [], 'prefix': 'pname-'},
        'pool_member': {'ignores': [], 'prefix': 'pmem-'},
        'vip': {'ignores': [], 'prefix': 'vip-'},
        'peer_group': {'ignores': [], 'prefix': 'AS'},
        'vrf': {
            'ignores': ['internet', 'dr', 'mgmt', 'management', 'mgt',
                        'default', 'wan'],
            'prefix': 'vrf-'},
        'serial': {'ignores': [], 'prefix': 'srl-'},
        'serialnum': {'ignores': [], 'prefix': 'snum-'},
        'networkId': {'ignores': [], 'prefix': 'netId-'},
        'address': {'ignores': [], 'prefix': 'addr-'},
        'url': {'ignores': [], 'prefix': 'url-'},
        'tags': {'ignores': [], 'prefix': 'tag-'},
        'orgId': {'ignores': [], 'prefix': 'org-'},
        'id': {'ignores': [], 'prefix': 'id-'},
        'zone': {'ignores': ['management', 'inside', 'outside', 'link', 'dmz',
                             'pci', 'ext', 'mgt', 'mgmt', 'int', 'vpn'],
                 'prefix': 'zone-'},
        'fwd': {'ignores': ['management', 'inside', 'outside', 'link', 'dmz',
                            'pci', 'ext', 'mgt', 'mgmt', 'int', 'vpn'],
                'prefix': 'fwd-'},
        'peer-group': {'ignores': [], 'prefix': 'pgrp-'},
        'hostname': {'ignores': ['management', 'inside', 'outside', 'link',
                                 'dmz', 'pci', 'ext', 'mgt', 'mgmt', 'int',
                                 'vpn'],
                     'prefix': 'hstname-'},
        'devicename': {
            'ignores': ['switch', 'sw', 'rtr', 'router', 'fw', 'firewall',
                        'local', 'vm'],
            'prefix': 'devn-'},
        'virtual-router': {
            'ignores': ['management', 'inside', 'outside', 'link', 'dmz',
                        'pci', 'ext', 'mgt', 'mgmt', 'int', 'vpn'],
            'prefix': 'vrtr-'},
    }


def get_columns_to_skip():
    # Define mapping for columns to skip based on table name.
    # Table/Column pairs listed here will be skipped when obscuring data.
    return {
        'IOS_HARDWARE_INVENTORY': ['name', 'description'],
        'PANOS_ALL_INTERFACES': ['name']
    }


# Create a random mapping and its reverse
chars = string.ascii_letters  # Only letters are included
shuffled_chars = list(chars)
random.shuffle(shuffled_chars)

FORWARD_MAP = {c: s for c, s in zip(chars, shuffled_chars)}
REVERSE_MAP = {s: c for c, s in zip(chars, shuffled_chars)}


def random_map_transform(s: str) -> str:
    """Transform a string using a random character mapping.

    Args:
        s (str): Input string.

    Returns:
        str: Transformed string.
    """
    return ''.join(FORWARD_MAP.get(c, c) if not c.isdigit() else c for c in s)


def reverse_map_transform(s: str, reverse_map) -> str:
    """Reverse a transformed string back to its original form.

    Args:
        s (str): Transformed string.
        reverse_map (dict): The reverse mapping dictionary.

    Returns:
        str: Original string.
    """
    return ''.join(reverse_map.get(c, c) if not c.isdigit() else c for c in s)


def consistent_transform(s: str, ignores: list = [], prefix: str = '') -> str:
    """Consistently transform column values based on provided rules.

    Args:
        s (str): The original string to transform.
        ignores (list, optional): List of values to ignore while transforming.
            Defaults to [].
        prefix (str, optional): Prefix to add to the transformed string.
            Defaults to ''.

    Returns:
        str: Transformed string.
    """
    if not s:
        return s
    ignores = [ignore.lower() for ignore in ignores]
    s = str(s) if not isinstance(s, (str, bytes)) else s
    words = re.split(r'(\W+)', s)
    transformed_words = []
    for word in words:
        if word.lower() in ignores or word.isdigit() or not word.isalnum():
            transformed_words.append(word)
        else:
            transformed_words.append(random_map_transform(word))
    return prefix + ''.join(transformed_words) if prefix \
        else ''.join(transformed_words)


def copy_table_structure(source_cursor, dest_cursor, dest_conn,
                         table_name, table_type):
    """Copy the table structure from a source to a destination database

    Args:
        source_cursor: SQLite cursor object for the source database.
        dest_cursor: SQLite cursor object for the destination database.
        dest_conn: SQLite connection object for the destination database.
        table_name (str): Name of the table to copy.
        table_type (str): Type of table to create.
    """
    source_cursor.execute(f"SELECT sql FROM sqlite_master WHERE "
                          f"type='{table_type}' AND name='{table_name}';")
    create_table = source_cursor.fetchall()[0]
    create_table = create_table[0]
    dest_cursor.execute(create_table)
    dest_conn.commit()


def reverse_consistent_transform(s: str, reverse_map, ignores: list = [],
                                 prefix: str = '') -> str:
    """Reverse the transformation applied to a string back to its original
    value based on provided rules.

    Args:
        s (str): The transformed string.
        reverse_map (dict): The reverse mapping dictionary.
        ignores (list, optional): List of values to ignore while transforming.
            Defaults to [].
        prefix (str, optional): Prefix to remove from the transformed string.
            Defaults to ''.

    Returns:
        str: Original string.
    """
    if not s:
        return s

    # Remove the prefix if present
    if s.startswith(prefix):
        s = s[len(prefix):]

    ignores = [ignore.lower() for ignore in ignores]
    words = re.split(r'(\W+)', s)
    transformed_words = []

    for word in words:
        if word.lower() in ignores or word.isdigit() or not word.isalnum():
            transformed_words.append(word)
        else:
            transformed_words.append(reverse_map_transform(word, reverse_map))

    return ''.join(transformed_words)


def obfuscate_ips_in_db(db_path: str, ip_offset: int = 98765432):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get all tables in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    pattern = r'\b(25[0-4]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)(?:\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?|0)){3}(?:/\d{1,2})?(?::\d{1,5})?\b' # noqa

    for table in tables:
        table_name = table[0]
        if table_name == 'sqlite_sequence' or table_name == 'char_map':
            continue

        print(f"Processing IP obfuscation in table: {table_name}")

        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = [col[1] for col in cursor.fetchall()]

        for col in columns:
            cursor.execute(f'SELECT "{col}" FROM "{table_name}";')
            values = cursor.fetchall()

            for value in values:
                value = value[0]
                match = re.search(pattern, str(value))
                if match:
                    ip_with_extra = match.group(0)

                    # Handle CIDR notation
                    if '/' in ip_with_extra:
                        ip_part, extra = ip_with_extra.split('/')
                        if ":" in extra:  # CIDR + port
                            mask, port = extra.split(":")
                            transformed_ip = transform_ip(ip_part, ip_offset)
                            transformed_value =\
                                f"{transformed_ip}/{mask}:{port}"
                        else:  # Just CIDR
                            mask = extra
                            transformed_ip = transform_ip(ip_part, ip_offset)
                            transformed_value = f"{transformed_ip}/{mask}"
                    elif ":" in ip_with_extra:  # Just port
                        ip_part, port = ip_with_extra.split(":")
                        transformed_ip = transform_ip(ip_part, ip_offset)
                        transformed_value = f"{transformed_ip}:{port}"
                    else:  # Just IP
                        transformed_value = transform_ip(ip_with_extra,
                                                         ip_offset)

                    cursor.execute(
                        f'UPDATE "{table_name}" SET "{col}"=? WHERE "{col}"=?',
                        (transformed_value, value))

            conn.commit()

    conn.close()


def obfuscate_db_data(source_db_path: str, dest_db_path: str = None,
                      ip_offset: int = 98765432):
    """Obfuscate the database data from a source database to a destination
    database.

    Args:
        source_db_path (str): Path to the source SQLite database.
        dest_db_path (str, optional): Path to the destination SQLite database.

    Parameters
    ----------
    ip_offset : int, optional
        The offset value used for IP address obfuscation. This determines how
        much each octet in the IP address is adjusted during the obfuscation
        process. If not provided, it defaults to 98765432.
    """

    if not dest_db_path:
        dest_db_path = source_db_path.replace('.db', '-new.db', 1)

    if Path(dest_db_path).exists():
        raise FileExistsError(f"The db {dest_db_path} already exists.")

    source_conn = sqlite3.connect(source_db_path)
    source_cursor = source_conn.cursor()

    dest_conn = sqlite3.connect(dest_db_path)
    dest_cursor = dest_conn.cursor()

    columns_to_rename = get_columns_to_rename()
    skip_columns_for_tables = get_columns_to_skip()

    # Create and populate the mapping table
    dest_cursor.execute(
        "CREATE TABLE IF NOT EXISTS char_map (original TEXT, mapped TEXT);")
    for original, mapped in FORWARD_MAP.items():
        dest_cursor.execute(
            "INSERT INTO char_map (original, mapped) VALUES (?, ?);",
            (original, mapped))
    dest_conn.commit()

    source_cursor.execute("SELECT name,type FROM sqlite_master order by type;")
    tables = source_cursor.fetchall()

    for table in tables:
        table_name = table[0]
        table_type = table[1]
        print(f"Processing Name obfuscation in table: {table_name}")

        if (
            table_name == 'sqlite_sequence'
            or table_type not in ['table', 'view']
        ):
            continue

        copy_table_structure(source_cursor, dest_cursor, dest_conn,
                             table_name, table_type)

        if table_type == 'view':
            continue

        source_cursor.execute(f"SELECT * FROM {table_name};")
        rows = source_cursor.fetchall()

        for row in rows:
            source_cursor.execute(f"PRAGMA table_info({table_name});")
            columns = [col[1] for col in source_cursor.fetchall()]

            # Skip columns for this table if specified
            skip_columns = skip_columns_for_tables.get(table_name, [])

            new_values = []
            for col, original_value in zip(columns, row):
                if col in skip_columns:
                    new_values.append(original_value)
                    continue
                rules = columns_to_rename.get(col, {})
                if col in columns_to_rename:
                    new_value = consistent_transform(original_value, rules.get(
                        "ignores", []), prefix=rules.get("prefix", ""))
                else:
                    new_value = original_value
                new_values.append(new_value)

            placeholders = ", ".join(["?" for _ in new_values])
            dest_cursor.execute(
                f"INSERT INTO {table_name} VALUES ({placeholders})",
                tuple(new_values))

        dest_conn.commit()

    source_conn.close()
    dest_conn.close()
    # After the main logic is done, call the IP obfuscation function
    obfuscate_ips_in_db(dest_db_path, ip_offset)


def reverse_db_data(source_db_path: str, dest_db_path: str):
    """Reverse the obfuscation of database data from a source to a destination
    database.

    Args:
        source_db_path (str): Path to the source SQLite database.
        dest_db_path (str): Path to the destination SQLite database.
    """
    source_conn = sqlite3.connect(source_db_path)
    source_cursor = source_conn.cursor()

    dest_conn = sqlite3.connect(dest_db_path)
    dest_cursor = dest_conn.cursor()

    columns_to_rename = get_columns_to_rename()
    skip_columns_for_tables = get_columns_to_skip()

    source_cursor.execute("SELECT original, mapped FROM char_map;")
    char_map_data = source_cursor.fetchall()
    reverse_map = {mapped: original for original, mapped in char_map_data}

    source_cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table';")
    tables = source_cursor.fetchall()

    for table in tables:
        table_name = table[0]
        if table_name == 'sqlite_sequence' or table_name == 'char_map':
            continue

        copy_table_structure(source_cursor, dest_cursor, dest_conn, table_name)

        source_cursor.execute(f"SELECT * FROM {table_name};")
        rows = source_cursor.fetchall()

        for row in rows:
            source_cursor.execute(f"PRAGMA table_info({table_name});")
            columns = [col[1] for col in source_cursor.fetchall()]

            # Skip columns for this table if specified
            skip_columns = skip_columns_for_tables.get(table_name, [])

            new_values = []
            for col, original_value in zip(columns, row):
                if col in skip_columns:
                    new_values.append(original_value)
                    continue
                rules = columns_to_rename.get(col, {})
                if col in columns_to_rename:
                    new_value = reverse_consistent_transform(original_value,
                                                             reverse_map,
                                                             rules.get(
                                                                 "ignores",
                                                                 []),
                                                             prefix=rules.get(
                                                                 "prefix", ""))
                else:
                    new_value = original_value
                new_values.append(new_value)

            placeholders = ", ".join(["?" for _ in new_values])
            dest_cursor.execute(
                f"INSERT INTO {table_name} VALUES ({placeholders})",
                tuple(new_values))

        dest_conn.commit()

    source_conn.close()
    dest_conn.close()


# Test functions
def test_random_map_transform_and_reverse():
    test_str = "msp-core-switch-01"
    print(
        f"Testing random_map_transform and reverse_map_transform with input: "
        f"'{test_str}'")

    transformed_str = random_map_transform(test_str)
    print(f"Transformed string: '{transformed_str}'")

    reversed_str = reverse_map_transform(transformed_str, REVERSE_MAP)
    print(f"Reversed string: '{reversed_str}'")

    assert reversed_str == test_str, \
        "Test for random_map_transform and reverse_map_transform failed."


def test_consistent_transform_and_reverse():
    test_str = "msp-core-switch-01"
    rules = {'ignores': ['switch'], 'prefix': 'test-'}
    print(
        f"Testing consistent_transform and "
        f"reverse_consistent_transform with input: '{test_str}'")

    transformed_str = consistent_transform(test_str, **rules)
    print(f"Transformed string: '{transformed_str}'")

    reversed_str = reverse_consistent_transform(transformed_str, REVERSE_MAP,
                                                **rules)
    print(f"Reversed string: '{reversed_str}'")

    assert reversed_str == test_str, ("Test for consistent_transform and "
                                      "reverse_consistent_transform failed.")


# Main test function
def test_module():
    print("Running tests...")

    test_random_map_transform_and_reverse()
    test_consistent_transform_and_reverse()

    print("All tests passed.")


if __name__ == "__main__":
    test_module()
