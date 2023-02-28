from typing import List, Tuple
import hashlib
import asyncio
from ndn.encoding import Name, Component, BinaryStr, InterestParam, TlvModel, FormalName
from ndn.types import Interest
from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout
from ndn.security import KeychainDigest
from ndn_python_repo import RepoCommandParameter, Version, ComponentVersion, ManifestMetaInfo, ManifestComponent
from ndn.encoding.tlv_model import VarBinaryStr, RepeatedField, BytesField

class FLIC:
    """
    Namespace for the TLV type assignments used in FLIC.
    """
    
    class Type:
        M_Name = 0x01
        M_Locator = 0x02
        M_Digest = 0x03
        M_NestedManifest = 0x04

class Manifest(TlvModel):
    """
    A class that represents a FLIC Manifest, containing various metadata and information about the data it represents.
    """
    class DataObject(TlvModel):
        type = 130
        digest = BytesField()

    class NameComponent(TlvModel):
        type = 7
        value = BytesField()

    class Name(TlvModel):
        type = 128
        components = RepeatedField(NameComponent)

    class Type(TlvModel):
        type = 129
        value = BytesField()

    class Version(TlvModel):
        type = 131
        value = BytesField()

    class Signature(TlvModel):
        type = 132
        value = BytesField()

    class NestedManifest(TlvModel):
        type = 133
        value = BytesField()

    type = 1
    data = RepeatedField(DataObject)
    name = Name()
    version = Version()
    signature = Signature()
    nested_manifest = NestedManifest()
    name = RepeatedField(BytesField(FLIC.Type.M_Name))
    locators = RepeatedField(BytesField(FLIC.Type.M_Locator))
    digests = RepeatedField(BytesField(FLIC.Type.M_Digest))
    nested_manifests = RepeatedField(BytesField(FLIC.Type.M_NestedManifest))

    @staticmethod
    def from_data(name: FormalName, data: BinaryStr, digest_algorithm: str = "sha256"):
        """
        Create a new Manifest from data bytes.

        :param name: Name of the Manifest.
        :param data: BinaryStr data of the Manifest.
        :param digest_algorithm: Digest algorithm to use when verifying the Manifest.
        :return: A new Manifest object.
        """
        manifest = Manifest()
        manifest.name.append(name)
        # Parse the Manifest TLV
        tlv = TlvModel.parse(data)
        if FLIC.Type.M_Locator in tlv:
            for locator in tlv[FLIC.Type.M_Locator]:
                manifest.locators.append(locator)
        if FLIC.Type.M_Digest in tlv:
            for digest in tlv[FLIC.Type.M_Digest]:
                manifest.digests.append(digest)
        if FLIC.Type.M_NestedManifest in tlv:
            for nested_manifest_data in tlv[FLIC.Type.M_NestedManifest]:
                nested_manifest = Manifest.from_data(name, nested_manifest_data, digest_algorithm=digest_algorithm)
                manifest.nested_manifests.append(nested_manifest)
        if FLIC.Type.M_Name in tlv:
            manifest.name = [FormalName.parse(name) for name in tlv[FLIC.Type.M_Name]]

        # Compute the hash value of the Manifest
        if digest_algorithm == "sha256":
            digest = hashlib.sha256(data).digest()
        else:
            raise ValueError(f"Unsupported digest algorithm: {digest_algorithm}")
        manifest.digests.append(digest)
        return manifest

    def __repr__(self):
        """
        Returns a string representation of the Manifest instance.
        """
        return "Manifest(name={}, locators={}, digests={})".format(
            repr(self.name), repr(self.locators), repr(self.digests))

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
        
    def add_nested_manifest(self, nested_manifest: 'Manifest') -> None:
        """
        Add a nested manifest to the manifest.

        :param nested_manifest: a Manifest instance to be nested in this manifest
        """
        self.nested_manifests.append(nested_manifest)
    def verify_signature(self, packet, manifest: 'Manifest') -> bool:
        """
        Verify the signature of a manifest.

        :param packet: The packet containing the manifest.
        :param manifest: The manifest to verify the signature of.
        :return: True if the signature is valid, False otherwise.
        """
        if packet.signature_info.type != 0:
            return False
        key_locator = packet.signature_info.key_locator
        if key_locator.name != manifest.name:
            return False
        if key_locator.key_name != manifest.name:
            return False
       
        
     def retrieve_manifest(self, app: NDNApp) -> 'Manifest':
    """
    Retrieve the manifest from a remote repository.

    Args:
        app: NDNApp object.

    Returns:
        Manifest object.
    """
    manifest_name = self._create_manifest_name()

    try:
        data_name, meta_info, content = await app.express_interest(
            manifest_name, need_raw_packet=True, can_be_prefix=True, lifetime=4000)
        packet = Data.from_content(content, metainfo=meta_info)
    except InterestTimeout:
        raise ValueError(f"Manifest not found for: {self.name}")
    except InterestNack as e:
        raise ValueError(f"Manifest not found for: {self.name}") from e

    if packet.content is None:
        raise ValueError(f"No content found in the manifest for: {self.name}")

    manifest_content = packet.content.get_value().to_bytes()
    manifest_tlv = Tlv.decode(bytes(manifest_content))
    manifest = Manifest.from_tlv(manifest_tlv)

    if not self.verify_signature(packet, manifest):
        raise ValueError("Invalid manifest signature")

    return manifest
