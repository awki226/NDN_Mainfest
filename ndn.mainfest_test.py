import abc
import asyncio as aio
import pytest
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestNack, InterestTimeout, ValidationFailure
from ndn.encoding import Component, Name, FormalName, SignaturePtrs
from ndn.transport.dummy_face import DummyFace
from ndn.security import KeychainDigest


class NDNAppTestSuite:
    app = None

    def test_main(self):
        aio.run(self.comain())

    async def comain(self):
        face = DummyFace(self.face_proc)
        keychain = KeychainDigest()
        self.app = NDNApp(face, keychain)
        face.app = self.app
        await self.app.main_loop(self.app_main())
        # self.app.run_forever(after_start=self.app_main())

    @abc.abstractmethod
    async def face_proc(self, face: DummyFace):
        pass

    @abc.abstractmethod
    async def app_main(self):
        pass


class TestImplicitSha256(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x2d\x07\x28\x08\x04test\x01\x20'
                                  b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
                                  b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
                                  b'\x0c\x01\x05'
                                  b'\x05\x2d\x07\x28\x08\x04test\x01\x20'
                                  b'\x54\x88\xf2\xc1\x1b\x56\x6d\x49\xe9\x90\x4f\xb5\x2a\xa6\xf6\xf9'
                                  b'\xe6\x6a\x95\x41\x68\x10\x9c\xe1\x56\xee\xa2\xc9\x2c\x57\xe4\xc2'
                                  b'\x0c\x01\x05')
        await face.input_packet(b'\x06\x13\x07\x06\x08\x04test\x14\x03\x18\x01\x00\x15\x04test')
        await aio.sleep(0.1)

    async def app_main(self):
        fut1 = self.app.express_interest(
            '/test/sha256digest=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            nonce=None, lifetime=5)
        fut2 = self.app.express_interest(
            '/test/sha256digest=5488f2c11b566d49e9904fb52aa6f6f9e66a954168109ce156eea2c92c57e4c2',
            nonce=None, lifetime=5)
        name2, _, content2 = await fut2
        with pytest.raises(InterestTimeout):
            await fut1
        assert name2 == Name.from_str('/test')
        assert content2 == b'test'
