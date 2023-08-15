import ctypes
from ctypes import wintypes


SECURITY_MAX_SID_SIZE = 68
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 0x00000001
WINBIO_FLAG_DEFAULT = 0x00000000
WINBIO_ID_TYPE_SID = 3

WINBIO_E_NO_MATCH = 0x09800580

lib = ctypes.WinDLL(r"C:\Windows\System32\winbio.dll")


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)
                ]


class AccountSid(ctypes.Structure):
    _fields_ = [("Size", wintypes.ULONG),
                ("Data", ctypes.c_ubyte * SECURITY_MAX_SID_SIZE)
                ]


class Value(ctypes.Union):
    _fields_ = [("NULL", wintypes.ULONG),
                ("Wildcard", wintypes.ULONG),
                ("TemplateGuid", GUID),
                ("AccountSid", AccountSid)
                ]


class WINBIO_IDENTITY(ctypes.Structure):
    _fields_ = [("Type", ctypes.c_uint32),
                ("Value", Value)]


class TOKEN_INFORMATION_CLASS:
    TokenUser = 1
    TokenGroups = 2
    TokenPrivileges = 3


class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", wintypes.BYTE*6)]

class SID(ctypes.Structure):
    _fields_ = [("Revision", wintypes.BYTE),
                ("SubAuthorityCount", wintypes.BYTE),
                ("IdentifierAuthority", SID_IDENTIFIER_AUTHORITY),
                ("SubAuthority", wintypes.DWORD)]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.POINTER(SID)),
                ("Attributes", wintypes.DWORD)]


class TOEKN_USER(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


class FingerPrint:
    def __init__(self):
        self.session_handle = ctypes.c_uint32()
        self.unit_id = ctypes.c_uint32()

        self.subfactor = ctypes.c_ubyte(0xf5)

        self.identity = WINBIO_IDENTITY()
        self.IsOpen = False

    def open(self):
        if self.IsOpen:
            return
        ret = lib.WinBioOpenSession(WINBIO_TYPE_FINGERPRINT,  # finger print
                                    WINBIO_POOL_SYSTEM,
                                    WINBIO_FLAG_DEFAULT,
                                    None,
                                    0,
                                    None,
                                    ctypes.byref(self.session_handle))  # pool   system
        if ret & 0xffffffff != 0x0:
            print("Open Failed!")
            return False
        self.IsOpen = True
        return True

    def locate_unit(self):
        ret = lib.WinBioLocateSensor(self.session_handle, ctypes.byref(self.unit_id))
        print(self.unit_id)
        if ret & 0xffffffff != 0x0:
            print("Locate Failed!")
            return False
        return True

    def identify(self):
        reject_detail = ctypes.c_uint32()
        ret = lib.WinBioIdentify(self.session_handle, ctypes.byref(self.unit_id), ctypes.byref(self.identity),
                                 ctypes.byref(self.subfactor),
                                 ctypes.byref(reject_detail))
        if ret & 0xffffffff != 0x0:
            print(hex(ret & 0xffffffff))
            raise Exception("Identify Error")
        print(f"Unit ID\t:{hex(self.unit_id.value)}")
        print(f"Sub Factor\t:{hex(self.subfactor.value)}")
        print(f"Identity Type\t: {self.identity.Type}")
        print(f"Identity AccountSid Data\t: {list(self.identity.Value.AccountSid.Data)[0:self.identity.Value.AccountSid.Size]}")
        print(f"Identity AccountSid Size\t: {self.identity.Value.AccountSid.Size}")
        print(f"Rejected Details:\t{hex(reject_detail.value)}")

    def verify(self):
        match = ctypes.c_bool(0)
        reject_detail = ctypes.c_uint32()
        # get identity
        self.get_current_user_identity()
        ret = lib.WinBioVerify(self.session_handle, ctypes.byref(self.identity),
                               self.subfactor, ctypes.byref(self.subfactor),
                               ctypes.byref(match), ctypes.byref(reject_detail))
        if ret & 0xffffffff == WINBIO_E_NO_MATCH or ret & 0xffffffff == 0:
            return match.value
        else:
            print(hex(ret & 0xffffffff))
            raise Exception("Identify Error")

    def close(self):
        if not self.IsOpen:
            return
        lib.WinBioCloseSession(self.session_handle)
        self.session_handle = 0

    def get_current_user_identity(self):
        self.get_token_information()

    @staticmethod
    def get_process_token():

        GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
        GetCurrentProcess.restype = wintypes.HANDLE
        OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
        OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
        OpenProcessToken.restype = wintypes.BOOL
        token = wintypes.HANDLE()

        TOKEN_READ = 0x20008
        res = OpenProcessToken(GetCurrentProcess(), TOKEN_READ, token)
        if not res > 0:
            raise RuntimeError("Couldn't get process token")
        return token

    def get_token_information(self):
        GetTokenInformation = ctypes.windll.advapi32.GetTokenInformation
        GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_uint,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ]
        GetTokenInformation.restype = wintypes.BOOL

        CopySid = ctypes.windll.advapi32.CopySid
        CopySid.argtypes = [
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p
        ]
        CopySid.restype = wintypes.BOOL

        GetLengthSid = ctypes.windll.advapi32.GetLengthSid
        GetLengthSid.argtypes = [
            ctypes.POINTER(SID)
        ]
        GetLengthSid.restype = wintypes.DWORD

        return_length = wintypes.DWORD(0)
        buffer = ctypes.create_string_buffer(SECURITY_MAX_SID_SIZE)

        res = GetTokenInformation(self.get_process_token(),
                                  TOKEN_INFORMATION_CLASS.TokenUser,
                                  buffer,
                                  SECURITY_MAX_SID_SIZE,
                                  ctypes.byref(return_length)
                                  )
        assert res > 0, "Error in second GetTokenInformation (%d)" % res

        token_user = ctypes.cast(buffer, ctypes.POINTER(TOEKN_USER)).contents
        CopySid(SECURITY_MAX_SID_SIZE,
                self.identity.Value.AccountSid.Data,
                token_user.User.Sid
                )
        self.identity.Type = WINBIO_ID_TYPE_SID
        self.identity.Value.AccountSid.Size = GetLengthSid(token_user.User.Sid)


if __name__ == '__main__':
    vb = FingerPrint()
    try:
        vb.open()
        print("Please touch the fingerprint sensor")
        if vb.verify():
            print("Accepted")
        else:
            print("Rejected")
    finally:
        vb.close()

