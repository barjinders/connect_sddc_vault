# Connect to VCenter and ESXi hosts using Credentails Stored in OCI Vault Secret. 

## Description
This script connects to the VC and ESXi hosts securely using credentails stored in OCI Vault Service.

The script first authenticates with the OCI Vault service using the appropriate credentials and permissions. Once authenticated, it would request access to the secret that contains the credentials required to connect to the VC.

Using the OCI Python SDK, the script then retrieves the required secret from the Vault service and extract the relevant credentials such as the username and password required for the VC connection. The script then uses the extracted credentials to connect to the VC.

To ensure the security of the secret credentials, the script leverage the encryption and decryption capabilities provided by the OCI Vault service.

Overall, this script provides a secure and efficient way to manage and use sensitive information required for connecting to a VC, while leveraging the powerful capabilities of the OCI Vault service.

## Usage 
1. Update the input.json file provided in the repo with the following details 

#### For each VC, update the values of the following parameters:
vc_host: The hostname or IP address of the vCenter server.
certificate_file_path: The path to the certificate file (in PEM format) for the vCenter server. If the server uses a self-signed certificate, set this value to null.
secret_id: The OCID of the secret containing the credentials required to authenticate with the vCenter server.

#### For each ESXi host, update the values of the following parameters:
esxi_host: The hostname or IP address of the ESXi host.
certificate_file_path: The path to the certificate file (in PEM format) for the ESXi host. If the host uses a self-signed certificate, set this value to null.
secret_id: The OCID of the secret containing the credentials required to authenticate with the ESXi host.

#### For OCI authentication, update the values of the following parameters:
oci_config_file: The path to the OCI configuration file, which contains the authentication details required to connect to OCI services.
oci_config_profile: The name of the profile in the OCI configuration file to use for authentication.
License
This JSON configuration file is licensed under the MIT License. See the LICENSE file for more information.

2. Run the script using the following command:
    python connect_to_vcenter.py

The script will read the configuration details from the input.json file and use them to connect to the vCenter server and ESXi hosts.

## Requirements
To run this script, you must have the following:

1. Python 3.x installed
2. The pyVmomi and oci Python libraries installed
3. A valid OCI account with appropriate permissions to access the required resources
4. Access to the vCenter server and ESXi hosts specified in the JSON configuration file

## Dependencies
This script relies on the following Python libraries:

1. pyVmomi
2. oci

## Acknowledgments
This script was inspired by and adapted from https://www.ateam-oracle.com/post/using-the-oci-instance-principals-and-vault-with-python-to-retrieve-a-secret. Special thanks to the authors for their contributions to the community.

## License
This Python script is licensed under the MIT License. See the LICENSE file for more information.