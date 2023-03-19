from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from pyVim.task import WaitForTasks
import ssl
import logging
import json
import oci
import base64


"""ESX Connection Functions"""
def connect_esx(hostname,username,password,context):
    service_instance = SmartConnect(host=hostname, user=username, pwd=password, port=443, sslContext=context)
    return (service_instance)

def get_esx_hosts(esxObj):
    host_si = []
    for host in esxObj:
        logging.info(f'Processing {host["esxi_host"]}...')
        context = setup_ssl_context(host["certificate_file_path"],hostname=host["esxi_host"])
        crd =host["creds"]
        crd = str(crd)
        username = crd.split(',')[0]
        password = crd.split(',')[1]
        si = connect_esx(host["esxi_host"],username,password,context)
        host_si.append(si)
    return host_si


"""VC Connection Functions """
def setup_ssl_context(cert_file=None,hostname=None):
    """
    Returns an SSL context with certificate verification enabled or disabled.

    Args:
        cert_file (str): Path to the certificate file.

    Returns:
        A `ssl.SSLContext` object.
    """
    logging.info(f'Setting SSL context for {hostname} with Certificate file {cert_file}')
    try:
        context = ssl.create_default_context(cafile=cert_file)
        if cert_file:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            prompt_for_certificate_verification()
        return context
    except ssl.SSLError:
        logging.exception("SSL error occurred while creating SSL context")
        raise

def prompt_for_certificate_verification():
    """
    Prompts the user to enable certificate verification and raises an exception if declined.
    """
    logging.warning("\n"*3+"*"*100)
    message = "Certificate verification is disabled.\n"+"*"*100+ "\nDo you want to continue with disable certificate verification? (yes/no): "
    user_input = input(message).casefold()
    if user_input in {"yes", "y"}:
        logging.debug("Certificate verification enabled by user")
    elif user_input in {"no", "n"}:
        raise ValueError("Certificate verification declined by user. Please provide a valid certificate file and try again.")
    else:
        logging.warning("Invalid input. Please enter 'yes' or 'no'.")
        prompt_for_certificate_verification()

def connect_to_vcenter(host, username, password, context):
    """
    Connect to a vCenter server using the provided credentials.

    Args:
        host (str): The hostname or IP address of the vCenter server.
        username (str): The username to use for authentication.
        password (str): The password to use for authentication.
        context (ssl.SSLContext): An optional SSL context to use for the connection.

    Returns:
        tuple: A tuple containing the vCenter content and the SmartConnect object.

    Raises:
        vim.fault.InvalidLogin: If the provided credentials are invalid.
        requests.exceptions.ConnectionError: If a connection to the vCenter server cannot be established.
    """
    logging.info("Connecting to VC.....")
    try:
        si = SmartConnect(host=host, user=username, pwd=password, sslContext=context)
        vc = si.RetrieveContent()
        return vc, si
    except vim.fault.InvalidLogin as e:
        logging.error("Invalid login credentials: %s", e)
        raise
    except Exception as e:
        logging.error("Failed to connect to vCenter: %s", e)
        raise

def get_cluster(vc):
    """
    Get a reference to the target cluster managed by the vCenter.
    """
    logging.info("Getting cluster object......")
    try:
        cluster = vc.viewManager.CreateContainerView(vc.rootFolder, [vim.ClusterComputeResource], True).view[0]
        return cluster
    except Exception as e:
        logging.error("Failed to retrieve the cluster information: %s", e)
        raise

"""Initiate Logging """
def _init_logging():

    # Get the root logger
    logger = logging.getLogger()

    # Set the logging level to INFO
    logger.setLevel(logging.INFO)

    # Create a formatter that includes the date and time
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Add a console handler and set its formatter to the created formatter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logging.info("Starting the script to add the host to the cluster, distributed virtual switch, VSAN and NSX...")

"""Gets Vault Secret with the OCID"""
def get_creds_from_vault(secret_client,secret_id):
    """
    Retrieves credentials from a secret vault using the provided secret client and secret ID.

    Parameters:
    secret_client (object): The secret client object used to retrieve the secret.
    secret_id (str): The ID of the secret to retrieve.

    Returns:
    str: The content of the retrieved secret.
    """
    try:
        response = secret_client.get_secret_bundle(secret_id)
    except Exception as e:
        logging.error(f"Error retrieving secret: {e}")
        return None

    base64_Secret_content = response.data.secret_bundle_content.content
    base64_secret_bytes = base64_Secret_content.encode('ascii')
    base64_message_bytes = base64.b64decode(base64_secret_bytes)
    secret_content = base64_message_bytes.decode('ascii')
    # Get the data from response
    return secret_content

def get_vault_creds(file):
    auth = read_json_file(file)
    auth_file_name = auth["oci"]["oci_config_file"]
    auth_profile_nmae = auth["oci"]["oci_config_profile"]
    config_data = get_oci_config(auth_file_name,auth_profile_nmae,)
    secret_client = oci.secrets.SecretsClient(config_data)
    for key, value in auth.items():
        if key == 'vc':
            logging.info(f"Getting creds for { value['vc_host']}")
            if value["secret_id"]:
                vc_creds = get_creds_from_vault(secret_client = secret_client,secret_id = value["secret_id"])
                logging.info(f"VC CREDS {vc_creds}")
                auth["vc"]["creds"] = vc_creds
            else:
                raise (f"Error!  { value['vc_host']} Secret OCID not valid! ")
        
        elif key == 'esxi_hosts':
            for host in value:
                logging.info(f"Getting creds for {host['esxi_host']}")
                #Check if the credentails are in OCI Vault Secret
                esxi_oci_secret_key =host["secret_id"]
                if esxi_oci_secret_key:
                    esx_creds = get_creds_from_vault(secret_client = secret_client,secret_id = esxi_oci_secret_key)
                    host["creds"] = esx_creds
                    logging.info(f"ESX CREDS {host['creds']}")
                else:
                    raise (f"Error! ESXi  {host['esxi_host']} Secret OCID not valid! ")
    return auth

"""Gets OCI Config with confile file and profile name """
def get_oci_config(config_file=None,profile_name=None):
    if(not config_file or not profile_name):
        config_file = input(f"The OCI config file to use (default: {oci.config.DEFAULT_LOCATION}): ") or oci.config.DEFAULT_LOCATION
        profile_name = input(f"The profile to use from the config file (default: {oci.config.DEFAULT_PROFILE}): ") or oci.config.DEFAULT_PROFILE
    logging.info("Running with:")
    logging.info(f"  Config:      {config_file}")
    logging.info(f"  Profile:     {profile_name}")
    try:
        config = oci.config.from_file(file_location=config_file, profile_name=profile_name)
    except oci.exceptions.ConfigFileNotFound as e:
        logging.error(f"Unable to locate configuration: {e}")
        raise SystemExit
    except oci.exceptions.InvalidConfig as e:
        logging.error(f"Unable to process config, missing profile '{profile_name}'?: {e}")
        raise SystemExit
    except oci.exceptions.ProfileNotFound as e:
        logging.error(f"Unable to locate profile: {e}")
        raise SystemExit
    if config:
        oci.config.validate_config(config)
    return config

""" User Input JSON File Functions """
def read_json_file(file_name):
    logging.info("Reading user input JSON file")
    try:
        with open(file_name, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"{file_name} not found.")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in {file_name}.")
        return None

def write_json_file(json_file, data):
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=4)

def validate_json_input(json_input):
    try:
        data = read_json_file(json_input)
        data.setdefault("vc", {})
        data["vc"].setdefault("vc_host", input("Please enter the value for vc_host: ") if not data["vc"].get("vc_host") else data["vc"]["vc_host"])
        data["vc"].setdefault("certificate_file_path", None)
        data["vc"].setdefault("secret_id", input("Please enter the value for secret_id: ") if not data["vc"].get("secret_id") else data["vc"]["secret_id"])

        data.setdefault("esxi_hosts", [])
        for esxi_host in data["esxi_hosts"]:
            esxi_host.setdefault("esxi_host", input("Please enter the value for esxi_host: ") if not esxi_host.get("esxi_host") else esxi_host["esxi_host"])
            esxi_host.setdefault("certificate_file_path", None)
            esxi_host.setdefault("secret_id", input("Please enter the value for secret_id: ") if not esxi_host.get("secret_id") else esxi_host["secret_id"])

        data.setdefault("oci", {})
        data["oci"].setdefault("oci_config_file",  input(f"The OCI config file to use (default: {oci.config.DEFAULT_LOCATION}): ") or oci.config.DEFAULT_LOCATION if not data["oci"].get("oci_config_file") else data["oci"]["oci_config_file"])
        data["oci"].setdefault("oci_config_profile",input(f"The profile to use from the config file (default: {oci.config.DEFAULT_PROFILE}): ") or oci.config.DEFAULT_PROFILE if not data["oci"].get("oci_config_profile") else data["oci"]["oci_config_profile"])
        get_oci_config(data["oci"]["oci_config_file"],data["oci"]["oci_config_profile"])
        
        # update the json_input file with user inputs
        write_json_file(json_input, data)
        return json.dumps(data, indent=4)
    except ValueError as e:
        print("Invalid JSON input:", e)

"""Print User Output"""
def print_vc_cluster(creds):
    vc_user = creds["vc"]["creds"].split(',')[0]
    vc_pass = creds["vc"]["creds"].split(',')[1]
    vc_host = creds["vc"]["vc_host"]
    vc_cert_path = creds["vc"]["certificate_file_path"]
    
    # Setup the SSL context
    vc_context = setup_ssl_context(cert_file=vc_cert_path,hostname = vc_host)

    # Connect to VC
    logging.info(f"inputs for VC connection {vc_host} {vc_user} {vc_pass}")
    vc = connect_to_vcenter(vc_host, vc_user, vc_pass, vc_context)

    #Get VC cluster
    cluster = get_cluster(vc[0])
    logging.info(f"\n\n\nVC Cluster Name {cluster.name}\n\n\n")
    Disconnect(vc[1])

def print_esxi_version(creds):
    esxDetails = creds["esxi_hosts"]
    hosts = get_esx_hosts(esxDetails)
    for x in hosts:
        logging.info(f"\n\n\nESXi host connected. Version of ESXi host: {x.RetrieveContent().about.version}\n\n\n")
        Disconnect(x)
    
def main():
    _init_logging()
    data = validate_json_input('input.json')
    if not data:
        raise ("Error! Invalid User Input File")
    creds = get_vault_creds('input.json')
    print_vc_cluster(creds)
    print_esxi_version(creds)

if __name__ == '__main__':
    main()