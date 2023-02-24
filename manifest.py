import hashlib
import struct
from typing import List, Tuple

from ndn.encoding import Name, Component
from ndn.types import InterestTimeout, InterestNack, InterestNetworkNack
from ndn.utils import timestamp


class Manifest:
    """
    Class representing an NDN manifest.

    Args:
        children (List[Tuple[Name, Component, int]]): a list of tuples representing child components of the manifest.
            Each tuple should contain a Name component, the component's type, and the component's freshness period (if
            applicable).

    Attributes:
        children (List[Tuple[Name, Component, int]]): a list of tuples representing child components of the manifest.
            Each tuple should contain a Name component, the component's type, and the component's freshness period (if
            applicable).
    """

    def __init__(self, children: List[Tuple[Name, Component, int]]):
        self.children = children

    def get_name(self) -> Name:
        """
        Get the Name of the manifest.

        Returns:
            Name: the Name of the manifest.
        """
        return Name.from_components([Component.from_bytes(b'\xFD'), Component.from_bytes(self.get_payload_hash())])

    def get_payload_hash(self) -> bytes:
        """
        Calculate the SHA256 hash of the manifest's children.

        Returns:
            bytes: the SHA256 hash of the manifest's children.
        """
        sha256 = hashlib.sha256()
        for name, component, freshness_period in self.children:
            sha256.update(name.to_bytes())
            sha256.update(bytes([component]))
            if freshness_period is not None:
                sha256.update(struct.pack('!I', freshness_period))
        return sha256.digest()

    def to_bytes(self) -> bytes:
        """
        Encode the manifest as a TLV structure.

        Returns:
            bytes: the encoded TLV structure representing the manifest.
        """
        result = bytearray()
        for name, component, freshness_period in self.children:
            result.extend(name.to_bytes())
            result.append(component)
            if freshness_period is not None:
                result.extend(struct.pack('!I', freshness_period))
        return bytes(result)

    @staticmethod
    def from_bytes(blob: bytes) -> 'Manifest':
        """
        Decode a TLV structure into a Manifest object.

        Args:
            blob (bytes): the TLV structure to decode.

        Returns:
            Manifest: the decoded manifest.
        """
        children = []
        offset = 0
        while offset < len(blob):
            name = Name.from_bytes(blob[offset:])
            offset += len(name)
            component = blob[offset]
            offset += 1
            freshness_period = None
            if offset + 4 <= len(blob) and component in [0x00, 0x01]:
                freshness_period = struct.unpack('!I', blob[offset:offset+4])[0]
                offset += 4
            children.append((name, component, freshness_period))
        return Manifest(children)

    def sign(self, key: bytes, digest_algorithm: str = 'sha256') -> Tuple[bytes, bytes]:
        """
        Sign the manifest using the specified private key and digest algorithm.

        Args:
            key (bytes): the private key to use for signing.
            digest_algorithm (str): the digest algorithm to use for signing (default 'sha256').

        Returns:
            Tuple[bytes, bytes]: the signature and the public key.
        """
        payload_hash = self.get_payload_hash()
        signer = hashlib.new(digest_algorithm)
        signer.update(bytes([0]))
        signer.update(payload_hash)
        signature
