#!/usr/bin/env python3

'''
Define Cisco DNAC collectors.
'''

import dnacentersdk
import pandas as pd


def create_api_object(base_url: str,
                      username: str,
                      password: str,
                      verify: bool = True) -> \
                      dnacentersdk.api.DNACenterAPI:
    """
    Create the object for making API calls to Cisco DNAC appliances.

    Args:
    ----
    base_url (str):
        The URL for the DNAC appliance.
    username (str):
        The username used to authenticate to the DNAC appliance.
    password (str):
        The password user to authenticate to the DNAC appliance.
    verify (bool, optional):
        Whether to verify SSL certificates. Defaults to True.

    Returns:
    ----
    dnac (dnacentersdk.api.DNACenterAPI):
        The object used for API calls.

    Examples:
    ----
    >>> from dnacentersdk import api
    >>> dnac = create_dnac_api_object('https://sandboxdnac.cisco.com/',
                                      username='devnetuser',
                                      password='Cisco123!',
                                      verify=False)
    >>> print(type(dnac))
    <class 'dnacentersdk.api.DNACenterAPI'>
    """
    dnac = dnacentersdk.api.DNACenterAPI(base_url=base_url,
                                         username=username,
                                         password=password,
                                         verify=verify)
    return dnac


def get_devices_modules(base_url: str,
                        username: str,
                        password: str,
                        verify: bool = True) -> pd.DataFrame:
    """
    Gets the module details for all devices in DNAC.

    Args:
    ----
    base_url (str):
        The URL for the DNAC appliance.
    username (str):
        The username used to authenticate to the DNAC appliance.
    password (str):
        The password user to authenticate to the DNAC appliance.
    verify (bool, optional):
        Whether to verify SSL certificates. Defaults to True.

    Returns:
    ----
    df (pd.DataFrame):
        A dataframe containing the details for the device modules.
    """
    # Get the devices from DNAC.
    df_devices = get_devices(base_url, username, password, verify=verify)

    # Create two lists. 'data' holds the modules for each device. 'df_data'
    # will contain the formatted data that is used to create the DataFrame.
    # It is not ideal to iterate over the responses twice, but it is necessary
    # since the DNAC API does not always return the same keys for each module
    # in its response.
    data = list()
    df_data = dict()

    # Iterate over the devices, getting the module details for each one.
    dnac = create_api_object(base_url, username, password, verify=verify)
    for idx, row in df_devices.iterrows():
        hostname = row['hostname']
        _id = row['id']
        response = dnac.devices.get_modules(_id)['response']

        for module in response:
            # Store the module along with the associated hostname and deviceId
            # in 'data'.
            module['hostname'] = hostname
            module['deviceId'] = _id
            data.append(module)

            # Iterate over the keys in 'module'. If the key does not exist in
            # 'df_data' then add it.
            for key in module:
                if not df_data.get(key):
                    df_data[key] = list()

    # Iterate over the list of modules inside 'data', adding them to 'df_data'.
    for module in data:
        for key in df_data:
            df_data[key].append(module.get(key))

    # Create the DataFrame, then move the 'hostname' and 'deviceId' columns to
    # the beginning of the DataFrame.
    df = pd.DataFrame.from_dict(df_data)
    to_move = ['hostname', 'deviceId']
    columns = df.columns.to_list()
    for column in to_move:
        columns.remove(column)

    new_column_order = to_move + columns
    df = df[new_column_order]

    return df


def get_devices(base_url: str,
                username: str,
                password: str,
                verify: bool = True) -> pd.DataFrame:
    """
    Get the list of devices from Cisco DNAC.

    Args:
    ----
    base_url (str):
        The URL for the DNAC appliance.
    username (str):
        The username used to authenticate to the DNAC appliance.
    password (str):
        The password user to authenticate to the DNAC appliance.
    verify (bool, optional):
        Whether to verify SSL certificates. Defaults to True.

    Returns:
    ----
    df (pd.DataFrame):
        A dataframe containing the device list.
    """
    dnac = create_api_object(base_url, username, password, verify=verify)
    devices = dnac.devices.get_device_list()

    # Create a dictionary called 'df_data', and add all of the keys from
    # 'devices' to it. The value of each key will be a list.
    df_data = dict()
    for item in devices['response']:
        for key in item:
            df_data[key] = list()

    # Populate 'df_data' with the values from 'devices'.
    for item in devices['response']:
        for key, value in item.items():
            df_data[key].append(value)

    # Create the DataFrame and return it.
    df = pd.DataFrame.from_dict(df_data)
    return df
