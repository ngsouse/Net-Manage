#!/usr/bin/env python3

'''
A library of functions for collecting data from network devices.
'''

import ansible_runner
import json
import pandas as pd
import re
import socket


def run_test(ansible_os,
             test_name,
             username,
             password,
             hostgroup,
             play_path,
             private_data_dir,
             nm_path,
             ansible_timeout='300'):
    '''
    This function calls the test that the user requested.

    Args:
        os (str):               The ansible_network_os variable
        test_name (str):        The name of the test that the user requested
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory
        nm_path (str):          The path to the Net-Manage repository
        interface (str):        The interface (defaults to all interfaces)
    '''
    if test_name == 'cam_table':
        if ansible_os == 'cisco.ios.ios':
            result = ios_get_cam_table(username,
                                       password,
                                       hostgroup,
                                       play_path,
                                       private_data_dir,
                                       nm_path)
        if ansible_os == 'cisco.nxos.nxos':
            result = nxos_get_cam_table(username,
                                        password,
                                        hostgroup,
                                        play_path,
                                        private_data_dir,
                                        nm_path)

    if test_name == 'arp_table':
        if ansible_os == 'paloaltonetworks.panos':
            result = panos_get_arp_table(username,
                                         password,
                                         hostgroup,
                                         play_path,
                                         private_data_dir)

    if test_name == 'interface_description':
        if ansible_os == 'cisco.ios.ios':
            result = ios_get_interface_descriptions(username,
                                                    password,
                                                    hostgroup,
                                                    play_path,
                                                    private_data_dir)

    if test_name == 'interface_status':
        if ansible_os == 'cisco.nxos.nxos':
            result = nxos_get_interface_status(username,
                                               password,
                                               hostgroup,
                                               play_path,
                                               private_data_dir)

    if test_name == 'find_uplink_by_ip':
        if ansible_os == 'cisco.ios.ios':
            result = ios_find_uplink_by_ip(username,
                                           password,
                                           hostgroup,
                                           play_path,
                                           private_data_dir)

    return result


def update_ouis(nm_path):
    '''
    Creates a dataframe of vendor OUIs. List is taken from
    https://standards-oui.ieee.org/. It is downloaded ahead of time to save
    time.

    There is a Python library for it, but it is prohibitively slow.

    To update the OUIs, save the data in https://standards-oui.ieee.org/ to
    Net-Manage/ouis.txt.

    Note: It might seem inefficient to parse the OUIs and create the
    dataframe as needed. However, it only takes 250ms~ to do, and the DataFrame
    size is only 500KB~. Therefore, I find the overhead acceptable.

    Args:
        nm_path (str): Path to the Net-Manage repository.

    Returns:
        df_ouis (DataFrame): A DataFrame containing the vendor OUIs
    '''
    with open(f'{nm_path}/ouis.txt', 'r') as f:
        data = f.read()
    pattern = '.*base 16.*'
    data = re.findall(pattern, data)
    data = [[_.split()[0], _.split('\t')[-1]] for _ in data]
    df_ouis = pd.DataFrame(data=data, columns=['base', 'vendor'])
    return df_ouis


def find_mac_vendor(addresses, df_ouis):
    '''
    Finds the vendor OUI for a list of MAC addresses.

    Note: This function could be improved by multi-threading. However, in
    testing I found the performance in its current state to be acceptable. It
    took about 30 seconds to get the vendors for 16,697 MAC addresses. That
    DOES include the time it took for Ansible to connect to the devices and get
    the CAM tables.

    Args:
        addresses (list): A list of MAC adddresses.

    Returns:
        vendors (list):   A list of vendors, ordered the same as 'addresses'
    '''
    # Convert MAC addresses to base 16
    addresses = [m.replace(':', str()) for m in addresses]
    addresses = [m.replace('-', str()) for m in addresses]
    addresses = [m.replace('.', str()) for m in addresses]
    addresses = [m[:6].upper() for m in addresses]
    # Create a list to store vendors
    vendors = list()

    # Create a list to store unknown vendors. This is used to keep from
    # repeatedly searching for vendor OUIs that are unknown
    unknown = list()

    # Create a dict to store known vendors. This is used to keep from
    # repeatedly searching df_ouis for vendors that are already discovered
    known = dict()

    # Search df_ouis for the vendor, add it to 'vendors', and return it
    for mac in addresses:
        vendor = known.get(mac)
        if not vendor:
            if mac in unknown:
                vendor = 'unknown'
            else:
                vendor_row = df_ouis.loc[df_ouis['base'] == mac]
                if len(vendor_row) > 0:
                    vendor = vendor_row['vendor'].values[0]
                else:
                    vendor = 'unknown'
                    unknown.append(mac)
        vendors.append(vendor)
    return vendors


def ios_find_uplink_by_ip(username,
                          password,
                          host_group,
                          play_path,
                          private_data_dir,
                          subnets=list()):
    '''
    Searches the hostgroup for a list of subnets (use /32 to esarch for a
    single IP). Once it finds them, it uses CDP and LLDP (if applicable) to try
    to find the uplink.

    If a list of IP addresses is not provided, it will attempt to find the
    uplinks for all IP addresses on the devices.

    This is a simple function that was writting for a single use case. It has
    some limitations:

    1. There is not an option to specify the VRF (although it will still return
       the uplinks for every IP that meets the parameters)
    2. If CDP and LLDP are disabled or the table is not populated, it does not
       try alternative methods like interface descriptions and CAM tables. I
       can add those if there is enough interest in this function.

    TODOs:
    - Add alternative methods if CDP and LLDP do not work:
      - Interface descriptions
      - Reverse DNS (in the case of P2P IPs)
      - CAM table
    - Add option to specify the VRF (low priority)

    Args:
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory
        addresses (list):       (Optional) A list of one or more subnets to
                                search for. Use CIDR notation. Use /32 to
                                search for individual IPs. If no list is
                                provided then the function will try to find the
                                uplinks for all IP addresses on the devices.

    Returns:
        df_combined (DF):       A DataFrame containing IP > remote port mapping
    '''

    # Get the IP addresses on the devices in the host group
    df_ip = cisco_ios_get_interface_ips(username,
                                        password,
                                        host_group,
                                        play_path,
                                        private_data_dir)

    # Get the CDP neighbors for the device
    df_cdp = ios_get_cdp_neighbors(username,
                                   password,
                                   host_group,
                                   play_path,
                                   private_data_dir)

    # Remove the sub-interfaces from df_ip
    local_infs = df_ip['Interface'].to_list()
    local_infs = [inf.split('.')[0] for inf in local_infs]
    df_ip['Interface'] = local_infs

    # Attempt to find the neighbors for the interfaces that have IPs
    df_data = list()

    for idx, row in df_ip.iterrows():
        device = row['Device']
        inf = row['Interface']
        neighbor_row = df_cdp.loc[(df_cdp['Device'] == device) &
                                  (df_cdp['Local Inf'] == inf)]
        remote_device = list(neighbor_row['Neighbor'].values)
        if remote_device:
            remote_device = remote_device[0]
            remote_inf = list(neighbor_row['Remote Inf'].values)[0]
        else:
            remote_device = 'unknown'
            remote_inf = 'unknown'
        mgmt_ip = row['IP']
        df_data.append([device, mgmt_ip, inf, remote_device, remote_inf])
    # Create a DataFrame and return it
    cols = ['Device',
            'IP',
            'Local Interface',
            'Remote Device',
            'Remote Interface']
    df_combined = pd.DataFrame(data=df_data, columns=cols)

    return df_combined


def ios_get_cam_table(username,
                      password,
                      host_group,
                      play_path,
                      private_data_dir,
                      nm_path,
                      interface=None):
    '''
    Gets the IOS CAM table and adds the vendor OUI.

    Args:
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory
        nm_path (str):          The path to the Net-Manage repository
        interface (str):        The interface (defaults to all interfaces)

    Returns:
        df_cam (DataFrame):     The CAM table and vendor OUI
    '''
    if interface:
        cmd = f'show mac address-table interface {interface}'
    else:
        cmd = 'show mac address-table'
    extravars = {'username': username,
                 'password': password,
                 'host_group': host_group,
                 'commands': cmd}

    # Execute the pre-checks
    playbook = f'{play_path}/cisco_ios_run_commands.yml'
    runner = ansible_runner.run(private_data_dir=private_data_dir,
                                playbook=playbook,
                                extravars=extravars)

    # Parse the output and add it to 'data'
    df_data = list()
    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            event_data = event['event_data']

            device = event_data['remote_addr']

            output = event_data['res']['stdout'][0].split('\n')
            output = list(filter(None, output))
            pattern = '[a-zA-Z0-9]{4}\\.[a-zA-Z0-9]{4}\\.[a-zA-Z0-9]{4}'
            for line in output:
                for item in line.split():
                    valid = re.match(pattern, item)
                    if valid and line.split()[-1] != 'CPU':
                        mac = line.split()[1]
                        interface = line.split()[-1]
                        vlan = line.split()[0]
                        try:
                            vendor = find_mac_vendor(mac)
                        except Exception:
                            vendor = 'unknown'
                        df_data.append([device, interface, mac, vlan, vendor])

    # Define the dataframe columns
    cols = ['device',
            'interface',
            'mac',
            'vlan',
            'vendor']

    df_cam = pd.DataFrame(data=df_data, columns=cols)

    # Get the ARP table, map the IPs to the CAM table, and add them to 'df_cam'
    # TODO: Iterate through VRFs on devices that do not support 'vrf all'
    cmd = 'show ip arp'
    extravars = {'username': username,
                 'password': password,
                 'host_group': host_group,
                 'commands': cmd}

    # Execute 'show interface description' and parse the results
    playbook = f'{play_path}/cisco_ios_run_commands.yml'
    runner = ansible_runner.run(private_data_dir=private_data_dir,
                                playbook=playbook,
                                extravars=extravars)

    # Create a dict to store the ARP table
    ip_dict = dict()

    # Create a list to store the IP address for each MAC address. If there is
    # not an entry in the ARP table then an empty string will be added
    addresses = list()

    # Parse the output
    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            event_data = event['event_data']
            device = event_data['remote_addr']

            output = event_data['res']['stdout'][0].split('\n')
            output = list(filter(None, output))
            for line in output[1:]:
                mac = line.split()[3]
                ip = line.split()[1]
                ip_dict[mac] = ip

            for idx, row in df_cam.iterrows():
                mac = row['mac']
                if ip_dict.get(mac):
                    addresses.append(ip_dict.get(mac))
                else:
                    addresses.append(str())

    # Add the addresses list to 'df_cam' as a column
    df_cam['ip'] = addresses

    # Set the desired order of columns
    cols = ['device',
            'interface',
            # 'description',
            'mac',
            # 'ip',
            'vlan',
            'vendor']
    df_cam = df_cam[cols]

    # Sort by interface
    df_cam = df_cam.sort_values('interface')

    # Reset (re-order) the index
    df_cam.reset_index(drop=True, inplace=True)

    return df_cam


def ios_get_cdp_neighbors(username,
                          password,
                          host_group,
                          play_path,
                          private_data_dir,
                          interface=str()):
    '''
    Gets the CDP neighbors for a Cisco IOS device.

    Args:
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory
        interface (str):        The interface to get the neighbor entry for. If
                                not specified, it will get all neighbors.

    Returns:
        df_cdp (DataFrame):     A DataFrame containing the CDP neighbors
    '''
    cmd = 'show cdp neighbor detail | include Device ID|Interface'
    extravars = {'username': username,
                 'password': password,
                 'host_group': host_group,
                 'commands': cmd}

    # Execute the command
    playbook = f'{play_path}/cisco_ios_run_commands.yml'
    runner = ansible_runner.run(private_data_dir=private_data_dir,
                                playbook=playbook,
                                extravars=extravars)

    # Parse the results
    cdp_data = list()
    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            event_data = event['event_data']

            device = event_data['remote_addr']

            output = event_data['res']['stdout'][0].split('\n')
            pos = 1  # Used to account for multiple connections to same device
            for line in output:
                if 'Device ID' in line:
                    remote_device = line.split('(')[0].split()[2].split('.')[0]
                    local_inf = output[pos].split()[1].strip(',')
                    remote_inf = output[pos].split()[-1]
                    row = [device, local_inf, remote_device, remote_inf]
                    cdp_data.append(row)
                pos += 1
    # Create a dataframe from cdp_data and return the results
    cols = ['Device', 'Local Inf', 'Neighbor', 'Remote Inf']
    df_cdp = pd.DataFrame(data=cdp_data, columns=cols)
    return df_cdp


def ios_get_interface_descriptions(username,
                                   password,
                                   host_group,
                                   play_path,
                                   private_data_dir,
                                   interface=None):
    '''
    Gets IOS interface descriptions.

    Args:
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory
        interface (str):        The interface (defaults to all interfaces)

    Returns:
        df_desc (DataFrame):    The interface descriptions
    '''
    # Get the interface descriptions and add them to df_cam
    cmd = 'show interface description'
    extravars = {'username': username,
                 'password': password,
                 'host_group': host_group,
                 'commands': cmd}

    # Execute 'show interface description' and parse the results
    playbook = f'{play_path}/cisco_ios_run_commands.yml'
    runner = ansible_runner.run(private_data_dir=private_data_dir,
                                playbook=playbook,
                                extravars=extravars)
    # Create a list to store the rows for the dataframe
    df_data = list()
    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            event_data = event['event_data']

            device = event_data['remote_addr']

            output = event_data['res']['stdout'][0].split('\n')
            # Get the position of the 'Description' column (we cannot split by
            # spaces because some interface descriptions have spaces in them).
            pos = output[0].index('Description')
            for line in output[1:]:
                inf = line.split()[0]
                desc = line[pos:]
                df_data.append([device, inf, desc])

    # Create the dataframe and return it
    cols = ['device', 'interface', 'description']
    df_desc = pd.DataFrame(data=df_data, columns=cols)
    return df_desc


def cisco_ios_get_interface_ips(username,
                                password,
                                host_group,
                                play_path,
                                private_data_dir):
    '''
    Gets the IP addresses assigned to interfaces.

    Args:
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory

    Returns:
        df_ip (df):             A DataFrame containing the interfaces and IPs
    '''
    cmd = 'show ip interface | include line protocol|Internet address'
    extravars = {'username': username,
                 'password': password,
                 'host_group': host_group,
                 'commands': cmd}

    # Execute the command
    playbook = f'{play_path}/cisco_ios_run_commands.yml'
    runner = ansible_runner.run(private_data_dir=private_data_dir,
                                playbook=playbook,
                                extravars=extravars)

    # Parse the results
    ip_data = list()
    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            event_data = event['event_data']

            device = event_data['remote_addr']

            output = event_data['res']['stdout'][0].split('\n')
            output.reverse()  # Reverse the output to make it easier to iterate
            for line in output:
                if 'Internet address' in line:
                    ip = line.split()[-1]
                    pos = output.index(line)+1
                    inf = output[pos].split()[0]
                    status = output[pos].split()[-1]
                    row = [device, inf, ip, status]
                    ip_data.append(row)
    # Create a dataframe from ip_data and return it
    cols = ['Device', 'Interface', 'IP', 'Status']
    df_ip = pd.DataFrame(data=ip_data, columns=cols)
    return df_ip


def nxos_get_cam_table(username,
                       password,
                       host_group,
                       play_path,
                       private_data_dir,
                       nm_path,
                       interface=None):
    '''
    Gets the CAM table for NXOS devices and adds the vendor OUI.

    Args:
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory
        interface (str):        The interface (defaults to all interfaces)
        nm_path (str):          The path to the Net-Manage repository

    Returns:
        df_cam (DataFrame):     The CAM table and vendor OUI
    '''
    # Create a list of vendor OUIs
    df_ouis = update_ouis(nm_path)

    if interface:
        cmd = f'show mac address-table interface {interface}'
    else:
        cmd = 'show mac address-table'
    extravars = {'username': username,
                 'password': password,
                 'host_group': host_group,
                 'commands': cmd}

    # Execute the pre-checks
    playbook = f'{play_path}/cisco_nxos_run_commands.yml'
    runner = ansible_runner.run(private_data_dir=private_data_dir,
                                playbook=playbook,
                                extravars=extravars)

    # Define the RegEx pattern for a valid MAC address
    # pattern = '([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})'
    pattern = '.*[a-zA-Z0-9]{4}\\.[a-zA-Z0-9]{4}\\.[a-zA-Z0-9]{4}.*'

    # Create a list to store MAC addresses
    addresses = list()

    # Parse the output and add it to 'data'
    df_data = list()

    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            event_data = event['event_data']

            device = event_data['remote_addr']

            output = event_data['res']['stdout'][0]

            output = re.findall(pattern, output)
            for line in output:
                mac = line.split()[2]
                interface = line.split()[-1]
                vlan = line.split()[1]
                df_data.append([device, interface, mac, vlan])

    # Create the dataframe and return it
    cols = ['device',
            'interface',
            'mac',
            'vlan']
    df_cam = pd.DataFrame(data=df_data, columns=cols)

    # Get the OUIs and add them to df_cam
    addresses = df_cam['mac'].to_list()
    vendors = find_mac_vendor(addresses, df_ouis)
    df_cam['vendor'] = vendors

    # Return df_cam
    return df_cam


def nxos_get_interface_status(username,
                              password,
                              host_group,
                              play_path,
                              private_data_dir):
    '''
    Gets the interface status for NXOS devices.

    Args:
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory
        nm_path (str):          The path to the Net-Manage repository

    Returns:
        df_inf_status (DataFrame): The interface statuses
    '''
    cmd = 'show interface status'
    extravars = {'username': username,
                 'password': password,
                 'host_group': host_group,
                 'commands': cmd}

    # Execute the pre-checks
    playbook = f'{play_path}/cisco_nxos_run_commands.yml'
    runner = ansible_runner.run(private_data_dir=private_data_dir,
                                playbook=playbook,
                                extravars=extravars)

    # Parse the output and add it to 'data'
    df_data = list()

    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            event_data = event['event_data']

            device = event_data['remote_addr']

            output = event_data['res']['stdout'][0].split('\n')

            # Get the positions of the header columns (except Port and Name)
            header = output[1]
            pos_status = header.index('Status')
            pos_vlan = header.index('Vlan')
            pos_duplex = header.index('Duplex')
            pos_speed = header.index('Speed')
            pos_type = header.index('Type')

            # Parse the output and add it to 'df_data'
            for line in output[3:]:
                inf = line.split()[0]
                status = line[pos_status:pos_vlan]
                vlan = line[pos_vlan:pos_duplex]
                duplex = line[pos_duplex:pos_speed]
                speed = line[pos_speed:pos_type]
                inf_type = line[pos_type:]
                row = [device, inf, status, vlan, duplex, speed, inf_type]
                row = [_.strip() for _ in row]
                df_data.append(row)

    # Create the dataframe and return it
    cols = ['device',
            'interface',
            'status',
            'vlan',
            'duplex',
            'speed',
            'type']

    df_inf_status = pd.DataFrame(data=df_data, columns=cols)

    return df_inf_status


def panos_get_arp_table(username,
                        password,
                        host_group,
                        play_path,
                        private_data_dir,
                        interface=None,
                        reverse_dns=False):
    '''
    Gets the ARP table from a Palo Alto firewall.

    Args:
        username (str):         The username to login to devices
        password (str):         The password to login to devices
        host_group (str):       The inventory host group
        play_path (str):        The path to the playbooks directory
        private_data_dir (str): The path to the Ansible private data directory
        interface (str):        The interface (defaults to all interfaces)
        reverse_dns (bool):     Whether to run a reverse DNS lookup. Defaults
                                to False because the test can take several
                                minutes on large ARP tables.

    Returns:
        df_arp (DataFrame):     The ARP table
    '''
    if interface:
        cmd = f'show arp {interface}'
    else:
        cmd = 'show arp all'
    extravars = {'username': username,
                 'password': password,
                 'host_group': host_group,
                 'command': cmd}

    playbook = f'{play_path}/palo_alto_get_arp_table.yml'
    runner = ansible_runner.run(private_data_dir=private_data_dir,
                                playbook=playbook,
                                extravars=extravars)

    for event in runner.events:
        if event['event'] == 'runner_on_ok':
            event_data = event['event_data']
            device = event_data['remote_addr']
            output = event_data['res']['stdout']

            output = json.loads(output)
            output = output['response']['result']['entries']['entry']

            arp_table = list()
            for item in output:
                address = item['ip']
                age = item['ttl']
                mac = item['mac']
                inf = item['interface']
                # Lookup the OUI vendor
                try:
                    vendor = find_mac_vendor(mac)
                except Exception:
                    vendor = 'unknown'
                row = [device, address, age, mac, inf, vendor]
                # Perform a reverse DNS lookup if requested
                if reverse_dns:
                    try:
                        rdns = socket.getnameinfo((address, 0), 0)[0]
                    except Exception:
                        rdns = 'unknown'
                    row.append(rdns)
                arp_table.append(row)

    cols = ['Device',
            'Address',
            'Age',
            'MAC Address',
            'Interface',
            'Vendor']
    if reverse_dns:
        cols.append('Reverse DNS')

    df_arp = pd.DataFrame(data=arp_table, columns=cols)
    return df_arp
