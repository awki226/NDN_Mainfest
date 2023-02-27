from typing import List, Tuple
import hashlib
from ndn.encoding import Name, Component, BinaryStr, InterestParam
from ndn.types import Interest
from ndn.app import NDNApp
from ndn.encoding import Name, Component, TlvModel
from ndn.types import InterestNack, InterestTimeout
from ndn.app import NDNApp
from ndn.security import KeychainDigest
from ndn_python_repo import RepoCommandParameter, Version, ComponentVersion, ManifestMetaInfo, ManifestComponent
import hashlib
import asyncio

class Manifest:
    def __init__(self, name: Name, data: BinaryStr):
        """
        Initialize a Manifest object.
        """
        self.name = name
        self.data = data
        self.locators = []
        self.nested_manifests = []
        self.file_digest = None
    
        def __init__(self, name=None):
        """
        Constructs a new Manifest instance.
        """
        if name is None:
            self.name = Name()
        else:
            self.name = name

        self.locators = []
        self.digests = []

    def __repr__(self):
        """
        Returns a string representation of the Manifest instance.
        """
        return "Manifest(name={}, locators={}, digests={})".format(
            repr(self.name), repr(self.locators), repr(self.digests))

    def add_locator(self, locator):
        """
        Adds a Locator to the Manifest.

        :param locator: the Locator to add
        """
        self.locators.append(locator)

    def add_digest(self, digest):
        """
        Adds a digest to the Manifest.

        :param digest: the digest to add
        """
        self.digests.append(digest)

    def clear_locators(self):
        """
        Removes all Locators from the Manifest.
        """
        self.locators = []

    def clear_digests(self):
        """
        Removes all digests from the Manifest.
        """
        self.digests = []

    def generate_manifest(self):
        """
        Generates a manifest for the current state of the Manifest instance.

        :return: a Blob containing the manifest data
        """
        # Create a TLV dictionary for the manifest
        tlv = {}

        # Add the name
        tlv[FLIC.Type.M_Name] = self.name.encode()

        # Add the locators
        if len(self.locators) > 0:
            locators_tlv = []
            for locator in self.locators:
                locators_tlv.append(locator.encode())
            tlv[FLIC.Type.M_Locator] = Blob(Tlv.encode(locators_tlv))

        # Add the digests
        if len(self.digests) > 0:
            digests_tlv = []
            for digest in self.digests:
                digests_tlv.append(digest.encode())
            tlv[FLIC.Type.M_Digest] = Blob(Tlv.encode(digests_tlv))

        # Encode the TLV dictionary and return the resulting Blob
        return Blob(Tlv.encode(tlv))
    
    def set_file_digest(self, file_digest: Tuple[int, bytes]):
        """
        Set the file digest of the data represented by this manifest.
        """
        self.file_digest = file_digest

    def add_locator(self, locator: Tuple[str, int]):
        """
        Add a locator to the manifest.
        """
        self.locators.append(locator)

    def add_nested_manifest(self, nested_manifest: 'Manifest'):
        """
        Add a nested manifest to the manifest.
        """
        self.nested_manifests.append(nested_manifest)

    def encode(self) -> BinaryStr:
        """
        Encode the manifest using TLV.
        """
        manifest = []
        manifest.append(Component.from_number(0))
        manifest.append(self.name)

        if self.file_digest:
            manifest.append(Component.from_number(1))
            manifest.append(Component.from_bytes(self.file_digest[1]))

        if self.locators:
            locators = []
            for locator in self.locators:
                locator_comp = []
                locator_comp.append(Component.from_number(1))
                locator_comp.append(Component.from_str(locator[0]))
                locator_comp.append(Component.from_number(2))
                locator_comp.append(Component.from_number(locator[1]))
                locators.append(Component.from_sequence(locator_comp))
            manifest.append(Component.from_number(2))
            manifest.append(Component.from_sequence(locators))

        if self.nested_manifests:
            nested_manifests = []
            for nested_manifest in self.nested_manifests:
                nested_manifests.append(Component.from_bytes(nested_manifest.encode()))
            manifest.append(Component.from_number(3))
            manifest.append(Component.from_sequence(nested_manifests))

        return Component.from_sequence(manifest).encode()
    
  def verify_manifest(packet, manifest):
    """
    Verify that the packet is consistent with the manifest
    """
    if not isinstance(packet, Data):
        raise TypeError("Packet must be an instance of ndnpy.Data")

    if not isinstance(manifest, Manifest):
        raise TypeError("Manifest must be an instance of ndnpy.Manifest")

    if packet.name != manifest.name:
        raise ValueError("Packet name and manifest name do not match")

    # Verify signature
    pub_key = manifest.signature_info.key_locator.key_data
    if pub_key is None:
        raise ValueError("Manifest does not have a valid public key")

    sig_value = packet.signature_value
    data = packet.encode()
    sig_algo = manifest.signature_info.signature_type

    if sig_algo == SignatureType.SHA256_WITH_RSA:
        pub_key = rsa.import_key(pub_key)
        verifier = pkcs1_15.new(pub_key)
        digest = SHA256.new()
        digest.update(data)
        try:
            verifier.verify(digest, sig_value)
        except (ValueError, TypeError):
            raise ValueError("Invalid signature on packet")

    #TODO: ADD EXTRA SIGNATURE TYPES 

    # Verify name components
    manifest_n = manifest.name.components
    packet_n = packet.name.components

    if len(manifest_n) > len(packet_n):
        raise ValueError("Manifest has more components than packet name")

    for i, comp in enumerate(manifest_n):
        if comp.type == ComponentType.PARAMETERS_SHA256_DIGEST:
            # ignore
            continue
        if i >= len(packet_n):
            raise ValueError("Manifest component exceeds length of packet name")
        if comp != packet_n[i]:
            raise ValueError(f"Manifest component {comp} does not match packet name component {packet_n[i]}")

    # Verify content hash
    content_hash = packet.content.get_value().digest()
    if content_hash != manifest.content_digest:
        raise ValueError("Content hash in packet does not match manifest")

    # Verify metainfo
    packet_m = packet.metainfo
    manifest_m = manifest.metainfo

    if packet_m.content_type != manifest_m.content_type:
        raise ValueError("Packet and manifest have different content types")

    if packet_m.freshness_period != manifest_m.freshness_period:
        raise ValueError("Packet and manifest have different freshness periods")

    if packet_m.final_block_id != manifest_m.final_block_id:
        raise ValueError("Packet and manifest have different final block IDs")



def verify_hash(packet, manifest):
    """
    Verifies the hash of the packet against the hash in the manifest.
    :param packet: NDN packet
    :param manifest: Manifest object
    :return: True if verification passes, False otherwise
    """
    if not manifest.hash_algorithm:
        return False

    if manifest.hash_algorithm != HashType.SHA256:
        return False

    if not manifest.hash_value:
        return False

    # Compute hash value
    encoded_packet = packet.encode()
    computed_hash = sha256digest(encoded_packet)

    # Verify hash value
    if manifest.hash_value != computed_hash:
        return False

    return True

    def compute_digest(self) -> bytes:
        """
        Compute the SHA-256 digest of the manifest using TLV.
        """
        return hashlib.sha256(self.encode()).digest()

    def sign(self, app: NDNApp, key_name: Name, cert_name: Name, freshness_period: float = None) -> Interest:
        """
        Sign the manifest by signing an Interest that represents it.

        Args:
            app: NDNApp object.
            key_name: Name of the signing key.
            cert_name: Name of the certificate for the signing key.
            freshness_period: Freshness period of the Interest.
        """
        interest_name = self.name + [Component.from_number(FLIC)]
        interest_param = InterestParam(can_be_prefix=True, lifetime=freshness_period)
        interest = Interest(name=interest_name, can_be_prefix=True, lifetime=freshness_period)
        interest.param = interest_param
        app.put_key(key_name)
        app.put_key(cert_name)
        app.sign_interest(interest, key_name, cert_name)
        return interest
