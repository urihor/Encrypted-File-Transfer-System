VERSION_OF_SERVER = 3


class Client:

    def __init__(self, name, uuid):
        self.name = name  # string of the client's name
        self.uuid = uuid  # uuid object
        self.key = ""  # the public key
        self.files = []  # list of the files that this client sent


class Header:
    def __init__(self, code, size):
        self.version = VERSION_OF_SERVER
        self.code = code
        self.payload_size = size
