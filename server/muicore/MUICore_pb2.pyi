"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.internal.enum_type_wrapper
import google.protobuf.message
import typing
import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class MUILogMessage(google.protobuf.message.Message):
    """LogMessage and StateList message types have "MUI" in their names to distinguish them from those in mserialize

    """
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    CONTENT_FIELD_NUMBER: builtins.int
    content: typing.Text
    def __init__(self,
        *,
        content: typing.Text = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["content",b"content"]) -> None: ...
global___MUILogMessage = MUILogMessage

class MUIMessageList(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    MESSAGES_FIELD_NUMBER: builtins.int
    @property
    def messages(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___MUILogMessage]: ...
    def __init__(self,
        *,
        messages: typing.Optional[typing.Iterable[global___MUILogMessage]] = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["messages",b"messages"]) -> None: ...
global___MUIMessageList = MUIMessageList

class MUIState(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    STATE_ID_FIELD_NUMBER: builtins.int
    PC_FIELD_NUMBER: builtins.int
    state_id: builtins.int
    pc: builtins.int
    def __init__(self,
        *,
        state_id: builtins.int = ...,
        pc: builtins.int = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["pc",b"pc","state_id",b"state_id"]) -> None: ...
global___MUIState = MUIState

class MUIStateList(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    ACTIVE_STATES_FIELD_NUMBER: builtins.int
    WAITING_STATES_FIELD_NUMBER: builtins.int
    FORKED_STATES_FIELD_NUMBER: builtins.int
    ERRORED_STATES_FIELD_NUMBER: builtins.int
    COMPLETE_STATES_FIELD_NUMBER: builtins.int
    @property
    def active_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___MUIState]:
        """state categories in MUI - based on manticore enums StateStatus and StateList"""
        pass
    @property
    def waiting_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___MUIState]: ...
    @property
    def forked_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___MUIState]: ...
    @property
    def errored_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___MUIState]: ...
    @property
    def complete_states(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___MUIState]: ...
    def __init__(self,
        *,
        active_states: typing.Optional[typing.Iterable[global___MUIState]] = ...,
        waiting_states: typing.Optional[typing.Iterable[global___MUIState]] = ...,
        forked_states: typing.Optional[typing.Iterable[global___MUIState]] = ...,
        errored_states: typing.Optional[typing.Iterable[global___MUIState]] = ...,
        complete_states: typing.Optional[typing.Iterable[global___MUIState]] = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["active_states",b"active_states","complete_states",b"complete_states","errored_states",b"errored_states","forked_states",b"forked_states","waiting_states",b"waiting_states"]) -> None: ...
global___MUIStateList = MUIStateList

class ManticoreInstance(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    UUID_FIELD_NUMBER: builtins.int
    uuid: typing.Text
    def __init__(self,
        *,
        uuid: typing.Text = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["uuid",b"uuid"]) -> None: ...
global___ManticoreInstance = ManticoreInstance

class TerminateResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    def __init__(self,
        ) -> None: ...
global___TerminateResponse = TerminateResponse

class NativeArguments(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    PROGRAM_PATH_FIELD_NUMBER: builtins.int
    BINARY_ARGS_FIELD_NUMBER: builtins.int
    ENVP_FIELD_NUMBER: builtins.int
    SYMBOLIC_FILES_FIELD_NUMBER: builtins.int
    CONCRETE_START_FIELD_NUMBER: builtins.int
    STDIN_SIZE_FIELD_NUMBER: builtins.int
    ADDITIONAL_MCORE_ARGS_FIELD_NUMBER: builtins.int
    program_path: typing.Text
    @property
    def binary_args(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[typing.Text]: ...
    @property
    def envp(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[typing.Text]: ...
    @property
    def symbolic_files(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[typing.Text]: ...
    concrete_start: typing.Text
    stdin_size: typing.Text
    additional_mcore_args: typing.Text
    def __init__(self,
        *,
        program_path: typing.Text = ...,
        binary_args: typing.Optional[typing.Iterable[typing.Text]] = ...,
        envp: typing.Optional[typing.Iterable[typing.Text]] = ...,
        symbolic_files: typing.Optional[typing.Iterable[typing.Text]] = ...,
        concrete_start: typing.Text = ...,
        stdin_size: typing.Text = ...,
        additional_mcore_args: typing.Text = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["additional_mcore_args",b"additional_mcore_args","binary_args",b"binary_args","concrete_start",b"concrete_start","envp",b"envp","program_path",b"program_path","stdin_size",b"stdin_size","symbolic_files",b"symbolic_files"]) -> None: ...
global___NativeArguments = NativeArguments

class EVMArguments(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    CONTRACT_PATH_FIELD_NUMBER: builtins.int
    CONTRACT_NAME_FIELD_NUMBER: builtins.int
    SOLC_BIN_FIELD_NUMBER: builtins.int
    TX_LIMIT_FIELD_NUMBER: builtins.int
    TX_ACCOUNT_FIELD_NUMBER: builtins.int
    DETECTORS_TO_EXCLUDE_FIELD_NUMBER: builtins.int
    ADDITIONAL_FLAGS_FIELD_NUMBER: builtins.int
    contract_path: typing.Text
    contract_name: typing.Text
    solc_bin: typing.Text
    tx_limit: typing.Text
    tx_account: typing.Text
    @property
    def detectors_to_exclude(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[typing.Text]: ...
    additional_flags: typing.Text
    def __init__(self,
        *,
        contract_path: typing.Text = ...,
        contract_name: typing.Text = ...,
        solc_bin: typing.Text = ...,
        tx_limit: typing.Text = ...,
        tx_account: typing.Text = ...,
        detectors_to_exclude: typing.Optional[typing.Iterable[typing.Text]] = ...,
        additional_flags: typing.Text = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["additional_flags",b"additional_flags","contract_name",b"contract_name","contract_path",b"contract_path","detectors_to_exclude",b"detectors_to_exclude","solc_bin",b"solc_bin","tx_account",b"tx_account","tx_limit",b"tx_limit"]) -> None: ...
global___EVMArguments = EVMArguments

class AddressRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    class _TargetType:
        ValueType = typing.NewType('ValueType', builtins.int)
        V: typing_extensions.TypeAlias = ValueType
    class _TargetTypeEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[AddressRequest._TargetType.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        FIND: AddressRequest._TargetType.ValueType  # 0
        AVOID: AddressRequest._TargetType.ValueType  # 1
        CLEAR: AddressRequest._TargetType.ValueType  # 2
    class TargetType(_TargetType, metaclass=_TargetTypeEnumTypeWrapper):
        pass

    FIND: AddressRequest.TargetType.ValueType  # 0
    AVOID: AddressRequest.TargetType.ValueType  # 1
    CLEAR: AddressRequest.TargetType.ValueType  # 2

    ADDRESS_FIELD_NUMBER: builtins.int
    TYPE_FIELD_NUMBER: builtins.int
    address: builtins.int
    type: global___AddressRequest.TargetType.ValueType
    def __init__(self,
        *,
        address: builtins.int = ...,
        type: global___AddressRequest.TargetType.ValueType = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["address",b"address","type",b"type"]) -> None: ...
global___AddressRequest = AddressRequest

class TargetResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    def __init__(self,
        ) -> None: ...
global___TargetResponse = TargetResponse

class ManticoreRunningStatus(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    IS_RUNNING_FIELD_NUMBER: builtins.int
    is_running: builtins.bool
    def __init__(self,
        *,
        is_running: builtins.bool = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["is_running",b"is_running"]) -> None: ...
global___ManticoreRunningStatus = ManticoreRunningStatus

class StopServerRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    def __init__(self,
        ) -> None: ...
global___StopServerRequest = StopServerRequest

class StopServerResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    def __init__(self,
        ) -> None: ...
global___StopServerResponse = StopServerResponse