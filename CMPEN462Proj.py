import asyncio
from bleak import BleakClient
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt_message(public_key, message):
    """Encrypts a message using the provided public key."""
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

async def main():
    address = "device_address"  # BLE device address
    public_key_uuid = "public_key_uuid"  # UUID for the public key characteristic
    write_uuid = "write_uuid"  # UUID for the writable characteristic where you send data

    async with BleakClient(address) as client:
        # Read the public key from the BLE device
        public_key_bytes = await client.read_gatt_char(public_key_uuid)
        public_key = load_pem_public_key(public_key_bytes)

        # Encrypt a message using the retrieved public key
        message = "Hello, this is a test message from the client!"
        encrypted_message = encrypt_message(public_key, message)

        # Write the encrypted message back to the device
        await client.write_gatt_char(write_uuid, encrypted_message)
        print("Encrypted message sent to the device.")

if __name__ == "__main__":
    asyncio.run(main())
