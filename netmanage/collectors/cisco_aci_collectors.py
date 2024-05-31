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
    logger = hp.setup_logger()
    config = AppConfig()
    env_path = os.path.expanduser(env_path)

    def validate_env_path(env_path: str):
        if not os.path.exists(env_path):
            failure_msg = f"Error: could not find '{env_path}'. Does it exist?"
            logger.critical(failure_msg)
            raise Exception(failure_msg)
        load_dotenv(override=True, dotenv_path=env_path)

    validate_env_path(env_path)

    def create_jobs_timestamp(config):
        now = datetime.now()
        setattr(config, "timestamp", now.strftime("%Y-%m-%d %H:%M:%S.%f"))

    create_jobs_timestamp(config)

    def get_path_variables(config):
        path_vars = {
            "db_path": hp.get_expanded_path("database_path")
            + "/"
            + hp.get_expanded_path("database_name"),
            "divergence_path": hp.get_expanded_path("divergence_path"),
            "logs_db": hp.get_expanded_path("logs_db"),
            "utils_db": hp.get_expanded_path("utils_db"),
            "artifacts_path": hp.get_expanded_path("artifacts_path"),
        }
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
            sites = hp.strip_list_spaces(sites.split(","))
            sites = hp.remove_duplicates(sites)
        if sites:
            aci_sites = {k: {} for k in sites}
            for site in sites:
                aci_sites[site]["site_name"] = site
                fixed_site = site.replace(" ", "-")

                aci_sites[site]["apic_urls"] = []
                try:
                    apic_urls = os.environ.get(
                        f"aci_sites_{fixed_site}_apic_urls"
                    ).split(",")
                    apic_urls = hp.strip_list_spaces(apic_urls)
                    apic_urls = hp.remove_duplicates(apic_urls)
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

                aci_sites[site]["username"] = os.environ.get(
                    f"aci_sites_{fixed_site}_username"
                )
                aci_sites[site]["password"] = os.environ.get(
                    f"aci_sites_{fixed_site}_password"
                )
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


def get_api_response(
    url: str, token: str, endpoint: str, verify: bool = True
) -> Optional[Dict[str, Any]]:
    """
    Performs an HTTP GET request to the specified APIC URL and retrieves data.

    Parameters
    ----------
    url : str
        The base URL of the ACI APIC to which the request is sent.
    token : str
        The authentication token used for the APIC session.
    endpoint : str
        The specific API endpoint to be appended to the base URL.
    verify : bool, optional
        A boolean indicating whether to verify the server's TLS certificate.
        Defaults to True.

    Returns
    -------
    Optional[Dict[str, Any]]
        A dictionary containing the response data, or None if an error occurs during the request.

    Raises
    ------
    HTTPError
        If the HTTP request returned an unsuccessful status code.
    Exception
        If any other exception occurred during the request.
    """
    logger = hp.setup_logger()
    headers = {"Cookie": f"APIC-cookie={token}"}
    full_url = f"{url}/{endpoint}"

    try:
        response = requests.get(full_url, headers=headers, verify=verify)
        response.raise_for_status()
        return response.json()
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        logger.error(f"An error occurred: {err}")

    return None


def process_api_response(response: Optional[Dict[str, Any]], key: str) -> pd.DataFrame:
    """
    Processes the API response data and converts it into a Pandas DataFrame.

    Parameters
    ----------
    response : Optional[Dict[str, Any]]
        The API response data.
    key : str
        The key to access the specific attributes within the response data.

    Returns
    -------
    pd.DataFrame
        A DataFrame containing the processed data.
    """
    if response:
        flattened_data = [item[key]["attributes"] for item in response["imdata"]]
        return pd.DataFrame(flattened_data)
    return pd.DataFrame()


def get_nodes_attributes(url: str, token: str, verify: bool = True) -> pd.DataFrame:
    """
    Retrieve node attributes from an ACI APIC.

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
    pd.DataFrame
        A DataFrame containing the node attributes.
    """
    response = get_api_response(url, token, "api/node/class/topSystem.json", verify)
    return process_api_response(response, "topSystem")


def get_site_subnets(url: str, token: str, verify: bool = True) -> pd.DataFrame:
    """
    Retrieve site subnets from an ACI APIC.

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
    pd.DataFrame
        A DataFrame containing the site subnets.
    """
    response = get_api_response(url, token, "api/node/class/fvSubnet.json", verify)
    df = process_api_response(response, "fvSubnet")

    if not df.empty:
        df[["address", "cidr"]] = df["ip"].str.split("/", expand=True)
        import ipaddress

        def get_network_ip(ip_with_cidr):
            network = ipaddress.ip_network(ip_with_cidr, strict=False)
            return str(network.network_address)

        df["network_ip"] = df["ip"].apply(get_network_ip)

    return df


def get_site_inventory(url: str, token: str, verify: bool = True) -> pd.DataFrame:
    """
    Retrieve site inventory from an ACI APIC.

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
    pd.DataFrame
        A DataFrame containing the site inventory.
    """
    response = get_api_response(url, token, "api/node/class/fabricNode.json", verify)
    return process_api_response(response, "fabricNode")


def get_site_client_endpoint_ips(
    url: str, token: str, verify: bool = True
) -> pd.DataFrame:
    """
    Retrieve site client endpoint IPs from an ACI APIC.

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
    pd.DataFrame
        A DataFrame containing the client endpoint IPs.
    """
    response = get_api_response(
        url, token, "api/node/class/fvIp.json?rsp-subtree=full", verify
    )
    return process_api_response(response, "fvIp")


def get_site_bridge_domains(url: str, token: str, verify: bool = True) -> pd.DataFrame:
    """
    Retrieve site bridge domains from an ACI APIC.

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
    pd.DataFrame
        A DataFrame containing the bridge domains.
    """
    response = get_api_response(url, token, "api/node/class/fvBD.json", verify)
    return process_api_response(response, "fvBD")


def save_collector(
    logger, config, site, params, collector_func, db_table, excluded_columns
):
    """
    Collects data from ACI site using the specified collector function and stores it in the database.

    Parameters
    ----------
    logger : logging.Logger
        Logger instance for logging messages.
    config : AppConfig
        Configuration object containing ACI site details and database path.
    site : str
        Name of the ACI site.
    params : dict
        Dictionary containing site parameters including APIC URLs and tokens.
    collector_func : function
        Function to collect data from the ACI site.
    db_table : str
        Name of the database table to store the collected data.
    excluded_columns : list
        List of columns to exclude from the database index.

    Returns
    -------
    None
    """
    token = params.get("token")
    if token:
        for url in params["apic_urls"]:
            msg = f"Collecting data from site '{site}' url: '{url}' using {collector_func.__name__}"
            logger.info(msg)
            df = collector_func(url, params["token"], verify=config.validate_certs)
            df.insert(len(df.columns), "site", site)
            if not df.empty:
                config.aci_sites[site]["apic_urls"] = hp.move_list_element_to_front(
                    config.aci_sites[site]["apic_urls"], url
                )
                break
        if not df.empty:
            id_cols = [col for col in df.columns if col not in excluded_columns]
            logger.info(f"site: {site}, records: {df.shape}")
            cah.store_results_in_db(
                df,
                config.db_path,
                db_table,
                config.timestamp,
                id_cols,
            )


def main(env_path: str):
    """
    Main function to set up the logger, load environment variables, authenticate to ACI sites,
    and collect various types of data from the sites.

    Parameters
    ----------
    env_path : str
        Path to the environment variables file.

    Returns
    -------
    None
    """
    logger = hp.setup_logger()
    config = load_environment_variables(env_path)

    for site, params in config.aci_sites.items():
        for url in params["apic_urls"]:
            logger.info(f"Getting auth token for site: {site}, url: {url}")
            token = cah.get_auth_token(
                url,
                params["username"],
                params["password"],
                verify=config.validate_certs,
            )
            if isinstance(token, str):
                config.aci_sites[site]["token"] = token
                config.aci_sites[site]["apic_urls"] = hp.move_list_element_to_front(
                    config.aci_sites[site]["apic_urls"], url
                )
                break
            setattr(config, "aci_token", None)

    data_collection_functions = [
        (
            get_site_bridge_domains,
            "CISCO_ACI_GET_SITE_bridge_domains",
            ["modTs", "lastStateModTs"],
        ),
        (
            get_site_inventory,
            "CISCO_ACI_GET_SITE_fabric_nodes",
            ["modTs", "lastStateModTs"],
        ),
        (
            get_site_client_endpoint_ips,
            "CISCO_ACI_GET_SITE_client_endpoint_ips",
            ["modTs"],
        ),
        (
            get_nodes_attributes,
            "CISCO_ACI_GET_NODES_ATTRIBUTES",
            ["clusterTimeDiff", "currentTime", "modTs", "systemUpTime"],
        ),
        (get_site_subnets, "CISCO_ACI_GET_SITE_SUBNETS", ["modTs"]),
    ]

    for func, db_table, excluded_columns in data_collection_functions:
        for site, params in config.aci_sites.items():
            save_collector(
                logger, config, site, params, func, db_table, excluded_columns
            )


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
