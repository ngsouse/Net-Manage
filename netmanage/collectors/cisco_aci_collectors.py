import argparse
import ast
import os
import pandas as pd
import requests
from datetime import datetime
from netmanage.helpers import cisco_aci_helpers as cah
from netmanage.helpers import helpers as hp
from dotenv import load_dotenv
from requests.exceptions import HTTPError
from typing import Any, Dict, Optional


class AppConfig:
    """
    A class to provide access to the application's configuration settings.

    Parameters
    ----------
    None

    Returns
    -------
    None
    """

    pass


def load_environment_variables(env_path: str) -> AppConfig:
    """
    Loads environment variables from a specified file.

    Parameters
    ----------
    env_path : str
        The full path to the environment file.

    Returns
    -------
    config : AppConfig
        An instance of AppConfig containing the deployment variables.
    """
    # Setup the logger
    logger = hp.setup_logger()

    # Create an instance of AppConfig to store the environment variables
    config = AppConfig()

    # Expand `env_path` if necessary
    env_path = os.path.expanduser(env_path)

    def validate_env_path(env_path: str):
        if not os.path.exists(env_path):
            failure_msg = f"Error: could not find '{env_path}'. Does it exist?"
            logger.critical(failure_msg)
            raise Exception(failure_msg)
        else:
            load_dotenv(override=True, dotenv_path=env_path)

    validate_env_path(env_path)

    def create_jobs_timestamp(config):
        now = datetime.now()
        setattr(config, "timestamp", now.strftime("%Y-%m-%d %H:%M:%S.%f"))
        # return now.strftime("%Y-%m-%d %H:%M:%S.%f")

    create_jobs_timestamp(config)

    def get_path_variables(config):
        path_vars = {
            "db_path": hp.get_expanded_path("database_path")
            + "/"
            + hp.get_expanded_path("database_name"),
            "divergence_path": hp.get_expanded_path("divergence_path"),
            "logs_db": hp.get_expanded_path("logs_db"),
            # "private_data_directory": hp.get_expanded_path("private_data_directory"),
            "utils_db": hp.get_expanded_path("utils_db"),
            "artifacts_path": hp.get_expanded_path("artifacts_path"),
        }
        # path_vars["playbooks_path"] = f"{path_vars['divergence_path']}/playbooks"
        missing_vars = []
        for key, value in path_vars.items():
            if value:
                setattr(config, key, value)
            else:
                missing_vars.append(key)

        if missing_vars:
            for line in missing_vars:
                logger.warning(f"Missing environment variable: {line}")

    get_path_variables(config)

    def get_aci_variables(config):
        sites = os.environ.get("aci_sites")
        if sites:
            # Formate 'sites' as a list; remove leading and trailing spaces from list
            # elements
            sites = hp.strip_list_spaces(sites.split(","))
            sites = hp.remove_duplicates(sites)
        if sites:
            # Create a dictionary of the ACI sites
            aci_sites = {k: {} for k in sites}
            for site in sites:
                # Add the site names to their respecitive keys
                aci_sites[site]["site_name"] = site
                # ACI allows site names to contain spaces. Since we cannot have spaces
                # in an environment file, we replaced them with hyphens.
                fixed_site = site.replace(" ", "-")

                # Get the APIC URLs for the site. Log a critical message if the APIC
                # URLs for the site are not in the environment file
                aci_sites[site]["apic_urls"] = []
                try:
                    apic_urls = os.environ.get(
                        f"aci_sites_{fixed_site}_apic_urls"
                    ).split(",")
                    # Remove leading and trailing spaces from the APIC URLs
                    apic_urls = hp.strip_list_spaces(apic_urls)
                    # Remove duplicate APIC URLs
                    apic_urls = hp.remove_duplicates(apic_urls)
                    # If any APIC URLs do not begin with "https://", then fix them
                    apic_urls = [
                        (
                            "https://" + url
                            if url.startswith("http://")
                            else (
                                "https://" + url
                                if not url.startswith("https://")
                                else url
                            )
                        )
                        for url in apic_urls
                    ]
                    aci_sites[site]["apic_urls"] = apic_urls
                except AttributeError as e:
                    if str(e) == "'NoneType' object has no attribute 'split'":
                        err_message = (
                            f"APIC URLs for site '{site}' appear to be missing."
                        )
                        logger.error(err_message)
                    else:
                        logger.error(str(e))

                # Get the APIC credentials for the site
                aci_sites[site]["username"] = os.environ.get(
                    f"aci_sites_{fixed_site}_username"
                )
                aci_sites[site]["password"] = os.environ.get(
                    f"aci_sites_{fixed_site}_password"
                )
                # Log a warning if the username and/or password is blank
                if not aci_sites[site]["username"]:
                    logger.warning(f"The username for site '{site}' is blank.")
                if not aci_sites[site]["password"]:
                    logger.warning(f"The password for site '{site}' is blank.")

            setattr(config, "aci_sites", aci_sites)

    get_aci_variables(config)

    def set_cert_validation_boolean(config):
        """
        Sets the boolean for cert validation. Right now, we enable or disable
        validation globally. In the future, we might want to expand it to be more
        granular.

        Parameters
        ----------
        config : object
            The object containing the variables for the deployment.

        Returns
        -------
        None
        """
        setattr(
            config, "validate_certs", ast.literal_eval(os.environ["validate_certs"])
        )

    set_cert_validation_boolean(config)

    return config


def get_nodes_attributes(
    url: str, token: str, verify: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Retrieve node attributes from an ACI APIC.

    This function performs an HTTP GET request to the specified APIC URL and retrieves
    attributes for all nodes. It uses an authentication token provided by the user.

    Parameters
    ----------
    url : str
        The base URL of the ACI APIC to which the request is sent.
    token : str
        The authentication token used for the APIC session.
    verify : bool, optional
        A boolean indicating whether to verify the server's TLS certificate.
        Defaults to True.

    Returns
    -------
    Optional[Dict[str, Any]]
        A dictionary containing the response data with node attributes, or None if
        an error occurs during the request.

    Raises
    ------
    HTTPError
        If the HTTP request returned an unsuccessful status code.
    Exception
        If any other exception occurred during the request.

    Examples
    --------
    >>> apic_url = 'https://apic.example.com'
    >>> apic_token = 'APIC_AUTH_TOKEN'
    >>> nodes_attributes = get_nodes_attributes(apic_url, apic_token)
    >>> print(nodes_attributes)

    Notes
    -----
    The function logs HTTP errors and other exceptions using a logger obtained from
    a helper function `hp.setup_logger()`.

    """
    logger = hp.setup_logger()

    headers = {"Cookie": f"APIC-cookie={token}"}
    url = f"{url}/api/node/class/topSystem.json"

    attributes = None

    try:
        response = requests.get(url, headers=headers, verify=verify)
        response.raise_for_status()  # Will raise HTTPError for 4xx and 5xx status codes
        attributes = response.json()
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        logger.error(f"An error occurred: {err}")

    # If any node attributes were returned, then add them to a DataFrame
    if attributes:
        flattened_data = [
            item["topSystem"]["attributes"] for item in attributes["imdata"]
        ]
        df = pd.DataFrame(flattened_data)
    else:
        df = pd.DataFrame()

    return df


def get_site_subnets(
    url: str, token: str, verify: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Retrieve site subnets from an ACI APIC.

    This function performs an HTTP GET request to the specified APIC URL and retrieves
    subnets for all bridge domains in a site. It uses an authentication token provided
    by the user.

    Parameters
    ----------
    url : str
        The base URL of the ACI APIC to which the request is sent.
    token : str
        The authentication token used for the APIC session.
    verify : bool, optional
        A boolean indicating whether to verify the server's TLS certificate.
        Defaults to True.

    Returns
    -------
    Optional[Dict[str, Any]]
        A dictionary containing the response data with site subnets, or None if
        an error occurs during the request.

    Raises
    ------
    HTTPError
        If the HTTP request returned an unsuccessful status code.
    Exception
        If any other exception occurred during the request.

    Examples
    --------
    >>> apic_url = 'https://apic.example.com'
    >>> apic_token = 'APIC_AUTH_TOKEN'
    >>> site_subnets = get_site_subnets(apic_url, apic_token)
    >>> print(site_subnets)

    Notes
    -----
    The function logs HTTP errors and other exceptions using a logger obtained from
    a helper function `hp.setup_logger()`.

    """
    logger = hp.setup_logger()

    headers = {"Cookie": f"APIC-cookie={token}"}
    url = f"{url}/api/node/class/fvSubnet.json"

    subnets = None

    try:
        response = requests.get(url, headers=headers, verify=verify)
        response.raise_for_status()  # Will raise HTTPError for 4xx and 5xx status codes
        subnets = response.json()
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        logger.error(f"An error occurred: {err}")

    # If any subnets were returned, then add them to a DataFrame
    if subnets:
        flattened_data = [item["fvSubnet"]["attributes"] for item in subnets["imdata"]]
        df = pd.DataFrame(flattened_data)
    else:
        df = pd.DataFrame()

    return df



def get_site_inventory(
    url: str, token: str, verify: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Retrieve site inventory from an ACI APIC.

    This function performs an HTTP GET request to the specified APIC URL and retrieves
    inventory for all bridge domains in a site. It uses an authentication token provided
    by the user.

    Parameters
    ----------
    url : str
        The base URL of the ACI APIC to which the request is sent.
    token : str
        The authentication token used for the APIC session.
    verify : bool, optional
        A boolean indicating whether to verify the server's TLS certificate.
        Defaults to True.

    Returns
    -------
    Optional[Dict[str, Any]]
        A dictionary containing the response data with site inventory, or None if
        an error occurs during the request.

    Raises
    ------
    HTTPError
        If the HTTP request returned an unsuccessful status code.
    Exception
        If any other exception occurred during the request.

    Examples
    --------
    >>> apic_url = 'https://apic.example.com'
    >>> apic_token = 'APIC_AUTH_TOKEN'
    >>> site_inventory = get_site_inventory(apic_url, apic_token)
    >>> print(site_inventory)

    Notes
    -----
    The function logs HTTP errors and other exceptions using a logger obtained from
    a helper function `hp.setup_logger()`.

    """
    logger = hp.setup_logger()

    headers = {"Cookie": f"APIC-cookie={token}"}
    url = f"{url}/api/node/class/fabricNode.json"

    inventory = None

    try:
        response = requests.get(url, headers=headers, verify=verify)
        response.raise_for_status()  # Will raise HTTPError for 4xx and 5xx status codes
        inventory = response.json()
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        logger.error(f"An error occurred: {err}")

    # If any inventory were returned, then add them to a DataFrame
    if inventory:
        flattened_data = [item["fabricNode"]["attributes"] for item in inventory["imdata"]]
        df = pd.DataFrame(flattened_data)
    else:
        df = pd.DataFrame()

    return df

def get_site_client_endpoint_ips(
    url: str, token: str, verify: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Retrieve site endpoints from an ACI APIC.

    This function performs an HTTP GET request to the specified APIC URL and retrieves
    endpoints for all bridge domains in a site. It uses an authentication token provided
    by the user.

    Parameters
    ----------
    url : str
        The base URL of the ACI APIC to which the request is sent.
    token : str
        The authentication token used for the APIC session.
    verify : bool, optional
        A boolean indicating whether to verify the server's TLS certificate.
        Defaults to True.

    Returns
    -------
    Optional[Dict[str, Any]]
        A dictionary containing the response data with site endpoints, or None if
        an error occurs during the request.

    Raises
    ------
    HTTPError
        If the HTTP request returned an unsuccessful status code.
    Exception
        If any other exception occurred during the request.

    Examples
    --------
    >>> apic_url = 'https://apic.example.com'
    >>> apic_token = 'APIC_AUTH_TOKEN'
    >>> site_client_endpoint_ips = get_site_client_endpoint_ips(apic_url, apic_token)
    >>> print(site_client_endpoint_ips)

    Notes
    -----
    The function logs HTTP errors and other exceptions using a logger obtained from
    a helper function `hp.setup_logger()`.

    """
    logger = hp.setup_logger()

    headers = {"Cookie": f"APIC-cookie={token}"}
    url = f"{url}/api/node/class/fvIp.json?rsp-subtree=full"

    endpoints = None

    try:
        response = requests.get(url, headers=headers, verify=verify)
        response.raise_for_status()  # Will raise HTTPError for 4xx and 5xx status codes
        endpoints = response.json()
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        logger.error(f"An error occurred: {err}")

    # If any endpoints were returned, then add them to a DataFrame
    if endpoints:
        flattened_data = [item["fvIp"]["attributes"] for item in endpoints["imdata"]]
        df = pd.DataFrame(flattened_data)
    else:
        df = pd.DataFrame()

    return df



def get_site_bridge_domains(
    url: str, token: str, verify: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Retrieve site bridge domains from an ACI APIC.

    This function performs an HTTP GET request to the specified APIC URL and retrieves
    bridge domains for all bridge domains in a site. It uses an authentication token provided
    by the user.

    Parameters
    ----------
    url : str
        The base URL of the ACI APIC to which the request is sent.
    token : str
        The authentication token used for the APIC session.
    verify : bool, optional
        A boolean indicating whether to verify the server's TLS certificate.
        Defaults to True.

    Returns
    -------
    Optional[Dict[str, Any]]
        A dictionary containing the response data with site endpoints, or None if
        an error occurs during the request.

    Raises
    ------
    HTTPError
        If the HTTP request returned an unsuccessful status code.
    Exception
        If any other exception occurred during the request.

    Examples
    --------
    >>> apic_url = 'https://apic.example.com'
    >>> apic_token = 'APIC_AUTH_TOKEN'
    >>> site_bridge_domains = get_site_bridge_domains(apic_url, apic_token)
    >>> print(site_bridge_domains)

    Notes
    -----
    The function logs HTTP errors and other exceptions using a logger obtained from
    a helper function `hp.setup_logger()`.

    """
    logger = hp.setup_logger()

    headers = {"Cookie": f"APIC-cookie={token}"}
    url = f"{url}/api/node/class/fvBD.json"

    endpoints = None

    try:
        response = requests.get(url, headers=headers, verify=verify)
        response.raise_for_status()  # Will raise HTTPError for 4xx and 5xx status codes
        endpoints = response.json()
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        logger.error(f"An error occurred: {err}")

    # If any endpoints were returned, then add them to a DataFrame
    if endpoints:
        flattened_data = [item["fvBD"]["attributes"] for item in endpoints["imdata"]]
        df = pd.DataFrame(flattened_data)
    else:
        df = pd.DataFrame()

    return df


def main(env_path: str):
    # Setup the logger
    logger = hp.setup_logger()

    # Load environment variables into a config object
    config = load_environment_variables(env_path)

    # Get the authentication tokens and add it to `config`
    # logger = hp.setup_logger()
    for site, params in config.aci_sites.items():
        # Try to get a token from each of the APIC URLs. The loop breaks on success. If
        # no APICs return a token, then the token for the site is set to None
        for url in params["apic_urls"]:
            logger.info(f"Getting auth token for site: {site}, url: {url}")
            token = cah.get_auth_token(
                url,
                params["username"],
                params["password"],
                verify=config.validate_certs,
            )
            # If a token was returned, add it to the appropriate site in `config` and
            # break out of the loop. Otherwise, set the site token in `config` to None
            # and keep iterating over APIC URLs until a token is found or all URLs have
            # been tried
            if isinstance(token, str):
                # Set the token in `config`
                config.aci_sites[site]["token"] = token
                # Move the APIC that provided the token to the beginning of the
                # `apic_urls` list for the site
                config.aci_sites[site]["apic_urls"] = hp.move_list_element_to_front(
                    config.aci_sites[site]["apic_urls"], url
                )
                break
            else:
                setattr(config, "aci_token", None)
    
    # Attempt to collect inventory from ACI sites
    for site, params in config.aci_sites.items():
        token = params.get("token")
        if token:
            msg = f"Collecting inventory attributes from site '{site}' url: '{url}'"
            logger.info(msg)
            # Use the token to get interface IP addresses
            for url in params["apic_urls"]:
                df = get_site_inventory(
                    url, params["token"], verify=config.validate_certs
                )
                # If site inventory were found then break out of the loop. Otherwise, proceed
                if not df.empty:
                    # Move the APIC that responded to the beginning of the `apic_urls`
                    # list for the site
                    config.aci_sites[site]["apic_urls"] = hp.move_list_element_to_front(
                        config.aci_sites[site]["apic_urls"], url
                    )
                    break
            # If site inventory were found then add them to the database
            if not df.empty:
                # Exclude these columns from being part of the index (this is to keep
                # the database from exploding)
                excluded = ["modTs", "lastStateModTs"]
                # Create the list of columns to use for the index, then add the nodes
                # attributes to the database
                id_cols = [_ for _ in df.columns.to_list() if _ not in excluded]
                logger.info(f"site: {site}, records: {df.shape}")
                cah.store_results_in_db(
                    df,
                    config.db_path,
                    "CISCO_ACI_GET_SITE_fabric_nodes",
                    config.timestamp,
                    id_cols,
                )

    # Attempt to collect client endpoint ips from ACI sites
    for site, params in config.aci_sites.items():
        token = params.get("token")
        if token:
            msg = f"Collecting endpoint attributes from site '{site}' url: '{url}'"
            logger.info(msg)
            # Use the token to get interface IP addresses
            for url in params["apic_urls"]:
                df = get_site_client_endpoint_ips(
                    url, params["token"], verify=config.validate_certs
                )
                breakpoint()
                # If endpoints were found then break out of the loop. Otherwise, proceed
                if not df.empty:
                    import sys
                    sys.exit()
                    # Move the APIC that responded to the beginning of the `apic_urls`
                    # list for the site
                    config.aci_sites[site]["apic_urls"] = hp.move_list_element_to_front(
                        config.aci_sites[site]["apic_urls"], url
                    )
                    break
            # If endpoints were found then add them to the database
            if not df.empty:
                # Exclude these columns from being part of the index (this is to keep
                # the database from exploding)
                excluded = ["modTs" ""]
                # Create the list of columns to use for the index, then add the nodes
                # attributes to the database
                id_cols = [_ for _ in df.columns.to_list() if _ not in excluded]
                logger.info(f"site: {site}, records: {df.shape}")
                cah.store_results_in_db(
                    df,
                    config.db_path,
                    "CISCO_ACI_GET_SITE_client_endpoint_ips",
                    config.timestamp,
                    id_cols,
                )

    # Attempt to collect node attributes from ACI sites
    for site, params in config.aci_sites.items():
        token = params.get("token")
        if token:
            # Use the token to get interface IP addresses
            for url in params["apic_urls"]:
                msg = f"Collecting node attributes from site '{site}' url: '{url}'"
                logger.info(msg)
                df = get_nodes_attributes(
                    url, params["token"], verify=config.validate_certs
                )
                # If nodes were found then break out of the loop. Otherwise, proceed
                if not df.empty:
                    # Move the APIC that responded to the beginning of the `apic_urls`
                    # list for the site
                    config.aci_sites[site]["apic_urls"] = hp.move_list_element_to_front(
                        config.aci_sites[site]["apic_urls"], url
                    )
                    break
            # If node attributes were found then add them to the database
            if not df.empty:
                # Exclude these columns from being part of the index (this is to keep
                # the database from exploding)
                excluded = [
                    "clusterTimeDiff",
                    "currentTime",
                    "modTs",
                    "systemUpTime",
                ]
                # Create the list of columns to use for the index, then add the nodes
                # attributes to the database
                id_cols = [_ for _ in df.columns.to_list() if _ not in excluded]
                logger.info(f"site: {site}, records: {df.shape}")
                cah.store_results_in_db(
                    df,
                    config.db_path,
                    "CISCO_ACI_GET_NODES_ATTRIBUTES",
                    config.timestamp,
                    id_cols,
                )

    # Attempt to collect subnets from ACI sites
    for site, params in config.aci_sites.items():
        token = params.get("token")
        if token:
            msg = f"Collecting subnet attributes from site '{site}' url: '{url}'"
            logger.info(msg)
            # Use the token to get interface IP addresses
            for url in params["apic_urls"]:
                df = get_site_subnets(
                    url, params["token"], verify=config.validate_certs
                )
                # If subnets were found then break out of the loop. Otherwise, proceed
                if not df.empty:
                    # Move the APIC that responded to the beginning of the `apic_urls`
                    # list for the site
                    config.aci_sites[site]["apic_urls"] = hp.move_list_element_to_front(
                        config.aci_sites[site]["apic_urls"], url
                    )
                    break
            # If subnets were found then add them to the database
            if not df.empty:
                # Exclude these columns from being part of the index (this is to keep
                # the database from exploding)
                excluded = ["modTs"]
                # Create the list of columns to use for the index, then add the nodes
                # attributes to the database
                id_cols = [_ for _ in df.columns.to_list() if _ not in excluded]
                logger.info(f"site: {site}, records: {df.shape}")
                cah.store_results_in_db(
                    df,
                    config.db_path,
                    "CISCO_ACI_GET_SITE_SUBNETS",
                    config.timestamp,
                    id_cols,
                )

    # for attr in dir(config):
    #     # Filter out special (magic) methods and attributes
    #     if not attr.startswith("__"):
    #         print(f"{attr} = {getattr(config, attr)}")
    # import sys

    # sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run data collection on Cisco ACI Fabrics."
    )
    parser.add_argument(
        "-e",
        "--env_path",
        required=True,
        help="Full path to the file containing environment variables.",
    )
    args = parser.parse_args()
    main(args.env_path)
