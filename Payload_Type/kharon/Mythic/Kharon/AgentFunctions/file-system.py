from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class CpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                cli_name="source",
                type=ParameterType.String,
                description="Source file/directory",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="destination",
                cli_name="destination",
                type=ParameterType.String,
                description="Destination file/directory",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) != 2:
                    raise ValueError("Usage: cp <src_path> <dest_path>")
                self.add_arg("source", parts[0])
                self.add_arg("destination", parts[1])

class CpCommand(CommandBase):
    cmd = "cp"
    needs_admin = False
    help_cmd = "cp -source <src_path> -destination <dest_path>"
    description = "Copy files/directories\nBehavior: Native Code\n"
    version = 1
    author = "@Oblivion"
    argument_class = CpArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "cp")
        source = task.args.get_arg("source")
        destination = task.args.get_arg("destination")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-source {source} to -destination {destination}",
            CommandName="fs"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        try:
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            success = Psr.Int32()
            
            if success:
                output = "File copied successfully"
            else:
                output = "Failed to copy file"
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )

class CdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                type=ParameterType.String,
                description="Path to change to (default: home directory)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("path", self.command_line.strip())

class CdCommand(CommandBase):
    cmd = "cd"
    needs_admin = False
    help_cmd = "cd -path [path]"
    description = "Change current working directory\nBehavior: Native Code\n"
    version = 1
    author = "@Oblivion"
    argument_class = CdArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        path = task.args.get_arg("path")
        task.args.add_arg("action", "cd")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="fs",
            DisplayParams=f"-path {path}"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        try:
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            output = Psr.Int32()

            if output:
                output = "directory changed with success"

            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )

class CatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.String,
                description="File to display",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("file", self.command_line.strip())

class CatCommand(CommandBase):
    cmd = "cat"
    needs_admin = False
    help_cmd = "cat -file <file>"
    description = "Display file contents\nBehavior: Native Code\n"
    version = 1
    author = "@Oblivion"
    argument_class = CatArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "cat")
        file_path = task.args.get_arg("file")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-file {file_path}",
            CommandName="fs"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        try:
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            output = Psr.Str()
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output.encode("utf-8", errors="ignore")
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )
    
class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                type=ParameterType.String,
                description="Path to list (default: current directory)",
                default_value=".",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("path", self.command_line.strip())

class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls -path [path]"
    description = "List directory contents\nBehavior: Native Code\n"
    version = 1
    author = "@ Oblivion"
    browser_script = BrowserScript( script_name="ls_new", author="@ Oblivion", for_new_ui=True )
    supported_ui_features = ["file_browser:list"]
    argument_class = LsArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "ls")
        path = task.args.get_arg("path")
        task.args.add_arg("path", path + "\\*" if path != "." else ".\\*")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-path {path}",
            CommandName="fs"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True
                )
                
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            output_data = []

            sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

            current_path = Psr.Str()

            if sub_id == SB_FS_LS:
                parent_dir = MythicRPCFileBrowserData(
                    IsFile=False,
                    Permissions="",
                    AccessTime="",
                    ModifyTime="",
                    Size=0,
                    UpdateDeleted=True,
                    Files=[]
                )
                
                file_list = []
                
                while Psr.buffer:
                    try:
                        file_info = OrderedDict()
                        file_info['Name'] = Psr.Str()
                        FileSize = Psr.Int32()
                        Attribute = Psr.Int32()
                        
                        if FileSize == -1:
                            file_info['Type'] = "<DIR>"
                            file_info['Size'] = None
                        else:
                            file_info['Type'] = "<FILE>"
                            file_info['Size'] = f"{FileSize}" 
                        
                        def TimePsr():
                            Day = Psr.Int16()
                            Month = Psr.Int16()
                            Year = Psr.Int16()
                            Hour = Psr.Int16()
                            Minute = Psr.Int16()
                            Second = Psr.Int16()
                            return f"{Year:04d}-{Month:02d}-{Day:02d} {Hour:02d}:{Minute:02d}:{Second:02d}"
                        
                        file_info['Created'] = TimePsr()
                        file_info['Accessed'] = TimePsr()
                        file_info['Modified'] = TimePsr()
                        
                        AttrMap = {
                            0x1: "R", 0x2: "H", 0x4: "S",
                            0x10: "D", 0x20: "A", 0x40: "N", 0x80: "T"
                        }
                        file_info['Attributes'] = "".join(v for k, v in AttrMap.items() if Attribute & k) or "?"
                        
                        child_entry = MythicRPCFileBrowserDataChildren(
                            Name=file_info['Name'],
                            IsFile=file_info['Type'] == "<FILE>",
                            Permissions=file_info['Attributes'],
                            AccessTime=file_info['Accessed'],
                            ModifyTime=file_info['Modified'],
                            Size=FileSize if file_info['Type'] == "<FILE>" else 0,
                        )
                        
                        parent_dir.Files.append(child_entry)
                        file_list.append(file_info)
                    
                    except struct.error:
                        break
                
                output_data = {
                    "DirectoryListing": file_list,
                    "Count": len(file_list)
                }

                await SendMythicRPCFileBrowserCreate(MythicRPCFileBrowserCreateMessage(
                    TaskID=task.Task.ID,
                    FileBrowser=parent_dir
                ))
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=json.dumps(output_data, indent=4).encode('utf-8')
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )

class MvArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                cli_name="source",
                type=ParameterType.String,
                description="Source file/directory",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="destination",
                cli_name="destination",
                type=ParameterType.String,
                description="Destination file/directory",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) != 2:
                    raise ValueError("Usage: mv <src_path> <dest_path>")
                self.add_arg("source", parts[0])
                self.add_arg("destination", parts[1])

class MvCommand(CommandBase):
    cmd = "mv"
    needs_admin = False
    help_cmd = "mv -source <src_path> -destination <dest_path>"
    description = "Move or rename files/directories\nBehavior: Native Code\n"
    version = 1
    author = "@Oblivion"
    argument_class = MvArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "mv")
        source = task.args.get_arg("source")
        destination = task.args.get_arg("destination")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-source {source} -destination {destination}",
            CommandName="fs"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        try:
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            success = Psr.Int32()
            
            if success:
                output = "File moved successfully"
            else:
                output = "Failed to move file"
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )

class PwdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass

class PwdCommand(CommandBase):
    cmd = "pwd"
    needs_admin = False
    help_cmd = "pwd"
    description = "Print current working directory\nBehavior: Native Code\n"
    version = 1
    author = "@Oblivion"
    argument_class = PwdArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "pwd")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="fs"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        try:
            RawResponse = bytes.fromhex(response)
            if RawResponse and RawResponse[0] == SB_FS_PWD:
                RawResponse = RawResponse[1:]
            Psr = Parser(RawResponse, len(RawResponse))
            output = Psr.Str()
            
            output = ''.join(char for char in output if char.isprintable())
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=output.encode()
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )

class RmArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                type=ParameterType.String,
                description="File/directory to remove",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("path", self.command_line.strip())

class RmCommand(CommandBase):
    cmd         = "rm"
    needs_admin = False
    help_cmd    = "rm -path <path>"
    description = "Remove files/directories\nBehavior: Native Code\n"
    version = 1
    author  = "@ Oblivion"
    argument_class = RmArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "rm")
        path = task.args.get_arg("path")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-path {path}",
            CommandName="fs"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
            
        try:
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            success = Psr.Int32()

            if success:
                success = f"file removed"
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"{success}"
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )
