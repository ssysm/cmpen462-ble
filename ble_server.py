import sys
import logging
import asyncio
import threading
import rsa

from typing import Any, Union

from bless import (  # type: ignore
    BlessServer,
    BlessGATTCharacteristic,
    GATTCharacteristicProperties,
    GATTAttributePermissions,
)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(name=__name__)

# NOTE: Some systems require different synchronization methods.
trigger: Union[asyncio.Event, threading.Event]
if sys.platform in ["darwin", "win32"]:
    trigger = threading.Event()
else:
    trigger = asyncio.Event()

client_public_key = None
comm_service_uuid = "A07498CA-AD5B-474E-940D-16F1FBE7E8CD".lower()
my_public_key_char_uuid = "51FF12BB-3ED8-46E5-B4F9-D64E2FEC021B".lower()
encrypted_hrm_char_uuid = "A07498CA-AD5B-474E-941D-16F1FBE7E8CD".lower()
client_public_key_char_uuid = "A07498CA-AD5B-474E-942D-16F1FBE7E8CD".lower()

def read_request(characteristic: BlessGATTCharacteristic, **kwargs) -> bytearray:
    logger.debug(f"Reading {characteristic.uuid}")
    if characteristic.uuid == encrypted_hrm_char_uuid:
        global client_public_key
        if client_public_key is None:
            logger.debug("Client public key not set")
            return b'\x3d\x93'
        return_data = rsa.encrypt(b"Hello HRM", client_public_key)
        logger.debug(f"Encrypted HRM data: {return_data}")
        server.get_characteristic(encrypted_hrm_char_uuid).value = return_data
        server.update_value(comm_service_uuid, encrypted_hrm_char_uuid)
    return characteristic.value


def write_request(characteristic: BlessGATTCharacteristic, value: Any, **kwargs):
    characteristic.value = value
    logger.debug(f"Char value set to {characteristic.uuid}")
    if characteristic.uuid == client_public_key_char_uuid:
        global client_public_key
        client_public_key = rsa.PublicKey.load_pkcs1(value, 'DER')
        logger.debug(f"Client public key: {client_public_key}")
    return  # No response


async def run(loop):
    trigger.clear()
    # Instantiate the server
    my_service_name = "RSA Service"
    global server
    server = BlessServer(name=my_service_name, loop=loop)
    server.write_request_func = write_request
    server.read_request_func = read_request

    logger.debug("Generating RSA keys")

    (pubkey, privkey) = rsa.newkeys(256)

    logger.debug(f"Public key: {pubkey.save_pkcs1('DER')}")

    # Add Service
    await server.add_new_service(comm_service_uuid)

    # Add a Characteristic to the service
    my_public_key_char_flags = (
        GATTCharacteristicProperties.read
        | GATTCharacteristicProperties.notify
    )

    encrypted_hrm_char_flags = (
        GATTCharacteristicProperties.read
        | GATTCharacteristicProperties.notify
    )

    client_public_key_char_flags = (
        GATTCharacteristicProperties.write
    )

    await server.add_new_characteristic(
        comm_service_uuid, 
        my_public_key_char_uuid,
        my_public_key_char_flags,
        None,
        GATTAttributePermissions.readable
    )
    
    await server.add_new_characteristic(
        comm_service_uuid, 
        encrypted_hrm_char_uuid,
        encrypted_hrm_char_flags,
        None,
        GATTAttributePermissions.readable
    )

    await server.add_new_characteristic(
        comm_service_uuid, 
        client_public_key_char_uuid,
        client_public_key_char_flags,
        None,
        GATTAttributePermissions.writeable
    )

    logger.debug(server.get_characteristic(my_public_key_char_uuid))
    logger.debug(server.get_characteristic(encrypted_hrm_char_uuid))

    server.get_characteristic(my_public_key_char_uuid).value = pubkey.save_pkcs1('DER')
    server.update_value(comm_service_uuid, my_public_key_char_uuid)

    await server.start()

    logger.info(server)

    while not await server.is_connected():  # The name of this method is slightly misleading
        await asyncio.sleep(0.1)
    logger.debug("Someone has subscribed.")

    while True:
        await asyncio.sleep(0.5)
    await server.stop()

loop = asyncio.get_event_loop()
loop.run_until_complete(run(loop))