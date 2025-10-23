import os
import base64
import requests
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobClient
from azure.security.attestation import AttestationClient, AttestationToken

load_dotenv()

KEY_VAULT_URL = os.environ.get("AZURE_KEY_VAULT_URL")
MASTER_KEY_SECRET_NAME = os.environ.get("MASTER_KEY_SECRET_NAME", "MasterEncryptionKey")
STORAGE_ACCOUNT_URL = os.environ.get("AZURE_STORAGE_ACCOUNT_URL")
STORAGE_CONTAINER_NAME = os.environ.get("AZURE_STORAGE_CONTAINER_NAME", "encrypted-data")
ATTESTATION_PROVIDER_URL = os.environ.get("ATTESTATION_PROVIDER_URL")

def get_master_key_from_vault() -> bytes:
    if not KEY_VAULT_URL:
        raise EnvironmentError("AZURE_KEY_VAULT_URL not found in environment or .env file.")
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
        secret = client.get_secret(MASTER_KEY_SECRET_NAME)
        master_key_bytes = base64.b64decode(secret.value)
        if len(master_key_bytes) < 32:
            raise ValueError("Retrieved key is too short. Expected 32 bytes.")
        print(f"  -> Successfully retrieved '{MASTER_KEY_SECRET_NAME}' from Azure Key Vault.")
        return master_key_bytes
    except Exception as e:
        print(f"  -> ERROR connecting to Azure Key Vault: {e}")
        raise

def upload_to_blob(blob_name: str, data: bytes):
    if not STORAGE_ACCOUNT_URL:
        raise EnvironmentError("AZURE_STORAGE_ACCOUNT_URL not found in environment or .env file.")
    try:
        blob_url = f"{STORAGE_ACCOUNT_URL}/{STORAGE_CONTAINER_NAME}/{blob_name}"
        credential = DefaultAzureCredential()
        blob_client = BlobClient.from_blob_url(blob_url=blob_url, credential=credential)
        blob_client.upload_blob(data, overwrite=True)
        print(f"  -> Encrypted blob uploaded to Azure Blob: {blob_name}")
    except Exception as e:
        print(f"  -> ERROR uploading to Azure Blob Storage: {e}")
        raise

def download_from_blob(blob_name: str) -> bytes:
    if not STORAGE_ACCOUNT_URL:
        raise EnvironmentError("AZURE_STORAGE_ACCOUNT_URL not found in environment or .env file.")
    try:
        blob_url = f"{STORAGE_ACCOUNT_URL}/{STORAGE_CONTAINER_NAME}/{blob_name}"
        credential = DefaultAzureCredential()
        blob_client = BlobClient.from_blob_url(blob_url=blob_url, credential=credential)
        download_stream = blob_client.download_blob()
        return download_stream.readall()
    except Exception as e:
        print(f"  -> ERROR downloading from Azure Blob Storage: {e}")
        raise

def get_azure_instance_metadata():
    try:
        url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        headers = {'Metadata': 'true'}
        response = requests.get(url, headers=headers, timeout=2)
        response.raise_for_status()
        return response.json()
    except Exception:
        return {}

def is_azure_confidential_vm():
    print("  -> Checking VM type for Confidential Compute capabilities...")
    metadata = get_azure_instance_metadata()
    vm_size = metadata.get('compute', {}).get('vmSize', '').lower()
    if vm_size.startswith('standard_dc'):
        print(f"  -> VM Type: {vm_size}. Confidential VM detected.")
        return True
    else:
        print(f"  -> VM Type: {vm_size}. Not a Confidential VM.")
        return False

def _get_attestation_report_from_vm():
    print("  -> Retrieving TEE hardware report from guest OS...")
    # NOTE: This part requires specific implementation based on the CVM environment (e.g., AMD SEV-SNP/Intel TDX)
    # and tools available in the guest OS (like sevtool or accessing /dev/sev).
    # Returning a placeholder as the real implementation is hardware/OS dependent.
    return b"actual-hardware-report-data"

def perform_real_attestation() -> bool:
    if not ATTESTATION_PROVIDER_URL:
        print("  -> ERROR: ATTESTATION_PROVIDER_URL not set in .env file.")
        return False
    try:
        print(f"  -> Contacting Azure Attestation Service at: {ATTESTATION_PROVIDER_URL}")
        credential = DefaultAzureCredential()
        attestation_client = AttestationClient(
            endpoint=ATTESTATION_PROVIDER_URL,
            credential=credential
        )
        report_data = _get_attestation_report_from_vm()
        runtime_data = {"nonce": base64.b64encode(os.urandom(16)).decode()}
        attestation_token = attestation_client.attest_sev_snp_vm(
            report_data,
            runtime_data=runtime_data
        )
        token_claims = attestation_token.get_body()
        if token_claims.get("x-ms-compliance-status") == "azure-compliant-cvm":
            print("  -> Attestation PASSED: TEE is an Azure-compliant Confidential VM.")
            return True
        else:
            print("  -> Attestation FAILED: TEE is not compliant.")
            return False
    except Exception as e:
        print(f"  -> Real attestation check FAILED with error: {e}")
        return False

def is_running_in_secure_enclave() -> bool:
    if not is_azure_confidential_vm():
        print("  -> Security Check FAILED: Not a recognized Confidential VM.")
        return False
    print("  -> Attempting real hardware attestation...")
    return perform_real_attestation()