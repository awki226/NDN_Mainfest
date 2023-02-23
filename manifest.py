import ndn.encoding as encoding
import ndn.types as types


class Manifest:
    """
    A manifest data structure that contains a list of Content Objects (Data in NDN) with application payload.

    The manifest can be encoded using the TLV format in NDN.
    """
    def __init__(self, content_list=None, signature_info=None, signature_value=None, locators=None):
        """
        Constructor for Manifest class.

        :param content_list: list of Content Objects (Data in NDN) with application payload
        :type content_list: list of ndn.types.Data
        :param signature_info: SignatureInfo object, defaults to None
        :type signature_info: ndn.types.SignatureInfo, optional
        :param signature_value: SignatureValue object, defaults to None
        :type signature_value: ndn.types.SignatureValue, optional
        :param locators: list of locators for the content, defaults to None
        :type locators: list of ndn.types.Locator, optional
        """
        self.content_list = content_list if content_list is not None else []
        self.signature_info = signature_info
        self.signature_value = signature_value
        self.locators = locators if locators is not None else []

    def add_content(self, content):
        """
        Add a Content Object (Data in NDN) to the manifest.

        :param content: Content Object (Data in NDN) with application payload
        :type content: ndn.types.Data
        """
        self.content_list.append(content)

    def encode(self):
        """
        Encode the manifest using the TLV format in NDN.

        :return: byte string of encoded manifest
        :rtype: bytes
        """
        manifest = types.ManifestData()
        for content in self.content_list:
            manifest.content.add(content)

        if self.signature_info is not None and self.signature_value is not None:
            manifest.signature_info = self.signature_info
            manifest.signature_value = self.signature_value

        for locator in self.locators:
            manifest.locator.add(locator)

        encoder = encoding.TTLEncoder()
        manifest.encode(encoder)
        return encoder.output()

    @classmethod
    def decode(cls, data):
        """
        Decode the encoded manifest using the TLV format in NDN.

        :param data: encoded manifest
        :type data: bytes
        :return: Manifest object
        :rtype: ndn.types.Manifest
        """
        decoder = encoding.TTLDecoder(data)
        manifest = types.ManifestData.parse(decoder)

        content_list = [content for content in manifest.content]
        signature_info = manifest.signature_info
        signature_value = manifest.signature_value
        locators = [locator for locator in manifest.locator]

        return cls(content_list, signature_info, signature_value, locators)

    def __repr__(self):
        return f"Manifest(content_list={self.content_list!r}, signature_info={self.signature_info!r}, " \
               f"signature_value={self.signature_value!r}, locators={self.locators!r})"
