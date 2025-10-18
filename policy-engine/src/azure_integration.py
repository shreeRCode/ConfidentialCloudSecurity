import os
import base64
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobClient

load_dotenv()

KEY_VAULT_URL = os.environ.get("AZURE_KEY_VAULT_URL")
MASTER_KEY_SECRET_NAME = os.environ.get("MASTER_KEY_SECRET_NAME", "MasterEncryptionKey")
STORAGE_ACCOUNT_URL = os.environ.get("AZURE_STORAGE_ACCOUNT_URL")
STORAGE_CONTAINER_NAME = os.environ.get("AZURE_STORAGE_CONTAINER_NAME", "encrypted-data")

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

def is_running_in_secure_enclave() -> bool:
    is_secure = os.environ.get("SECURE_ENVIRONMENT", "FALSE").upper() == "TRUE"
    
    if is_secure:
        print("  -> Security Check: PASSED. Running in a trusted environment.")
    else:
        print("  -> Security Check: FAILED. Not a trusted environment.")
        
    return is_secure