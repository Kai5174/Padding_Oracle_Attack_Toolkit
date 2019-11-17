BLOCK_SIZE = 16
import socket
import base64


class POACommunication:
    
    def __init__(self, ip, port=80):
        self.ip = ip
        self.port = port
        self.comm_type()
    
    def comm_type(self):
        """
        Override this if you are not using socket communication
        """
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.ip, self.port))
    
    def send(self, msg: bytes):
        """
        Override this if you are not using socket communication
        """
        self.s.send(msg)
    
    def recv(self) -> str:
        """
        Override this if you are not using socket communication
        """
        recv_msg = self.s.recv(1024)
        return recv_msg.decode('utf-8')

    
    def get_iv(self) -> bytes:
        """
        Get valid ciphertext to extract IV, Override this if situation is different
        """
        token = self.s.recv(1024)
        decoded_token = base64.b64decode(token)
        iv = decoded_token[:BLOCK_SIZE]
        return iv
    

class POAAnyEncrypt:

    def __init__(self, ip, port=80):
        """
        Override self.comm if using different communication class
        """
        self.ip = ip
        self.port = port
        self.comm = POACommunication(ip=ip, port=port)
    
    @staticmethod
    def pad(msg: str) -> str:
        app_len = BLOCK_SIZE - len(msg) % BLOCK_SIZE
        for ii in range(app_len):
            msg += chr(app_len)
        return msg
    
    @staticmethod
    def block_xor(a: bytearray, b: bytearray) -> bytearray:
        c = bytearray(b'\x00'*len(a))
        for ii in range(len(a)):
            c[ii] = a[ii]^b[ii]
        return c
    
    @staticmethod
    def get_current_C1(I0: bytearray, padding_value: int):
        padding_masker = bytearray(b'\x00'*BLOCK_SIZE)
    

    def encrypt_payload(self, payload: str):
        """
        C1 -- C0
        |      |
        P1 -- P0
        """
        P = bytearray(self.pad(payload).encode('utf-8'))
        iv = bytearray(self.comm.get_iv())
        C1 = bytearray(b'\x00'*BLOCK_SIZE)

        num_blocks = int(len(P)/BLOCK_SIZE)
        ciphertext_collection = []
        for ii in reversed(range(num_blocks)):
            P0 = P[ii * BLOCK_SIZE: (ii + 1) * BLOCK_SIZE]
            C0 = C1.copy()
            I0 = bytearray(b'\x00'*BLOCK_SIZE)
            for curr_index in reversed(range(BLOCK_SIZE)):
                padding_value = BLOCK_SIZE - curr_index
                # print(padding_value)

                masker = bytearray(b'\x00'*BLOCK_SIZE)
                for kk in range(padding_value):
                    masker[-kk-1] = padding_value
                C1 = self.block_xor(I0, masker)

                ciphertext = iv + C1 + C0
                iterate = 1
                while not self._is_padding_correct(base64.b64encode(bytes(ciphertext))):
                    C1[curr_index] = iterate
                    iterate += 1
                    ciphertext = iv + C1 + C0
                I0[curr_index] = C1[curr_index] ^ padding_value
            C1 = self.block_xor(P0, I0)
            ciphertext_collection.insert(0, C1)
        r_data = bytearray()
        for arrays in ciphertext_collection:
            r_data += arrays
        r_data = iv + r_data + bytearray(b'\x00'*BLOCK_SIZE)
        return r_data
    
    
    def _is_padding_correct(self, msg: bytes):
        self.comm.send(msg)
        recv = self.comm.recv()
        return self.__is_padding_correct(recv)

    def __is_padding_correct(self, recv: str):
        """
        Override this to identify different response
        """ 
        if recv == '0':
            return False
        else:
            return True


if __name__ == '__main__':
    data = input("any message? ")
    ip = '127.0.0.1'
    port = 8080
    poa = POAAnyEncrypt(ip, port)
    ciphertext = poa.encrypt_payload(data)
    print("="*16)
    print("the ciphertext is {}".format(base64.b64encode(ciphertext).decode('utf-8')))

    print("="*16)
    print("Try to verify it")
    poa.comm.send(b'verifyme: '+base64.b64encode(ciphertext))
    print("Check the server side to view the decrypted msg")

