"""代码中的一次静态调用线索。"""

from dataclasses import dataclass
from dataclasses import field


@dataclass(frozen=True)
class CodeCall:
    """保存调用名和能够直接从语法树确认的简单信息。"""

    name: str
    line: int
    receiver_type: str | None = None
    argument_count: int | None = None
    receiver_type_full_name: str | None = None
    receiver_method_owner_type: str | None = None
    receiver_method_name: str | None = None
    receiver_method_argument_count: int | None = None
    positional_argument_count: int | None = None
    keyword_argument_names: list[str] = field(default_factory=list)
    has_argument_unpacking: bool = False

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("调用名称不能为空")
        if self.line < 1:
            raise ValueError("调用行号必须大于或等于1")
        if self.receiver_type is not None and not self.receiver_type.strip():
            raise ValueError("调用接收者类型不能是空字符串")
        if self.receiver_type_full_name is not None and not self.receiver_type_full_name.strip():
            raise ValueError("调用接收者完整类型不能是空字符串")
        if self.argument_count is not None and self.argument_count < 0:
            raise ValueError("调用参数个数不能小于0")
        if self.positional_argument_count is not None and self.positional_argument_count < 0:
            raise ValueError("调用位置参数个数不能小于0")
        if any(not name.strip() for name in self.keyword_argument_names):
            raise ValueError("调用关键字参数名称不能为空")
        lookup_values = (
            self.receiver_method_owner_type,
            self.receiver_method_name,
            self.receiver_method_argument_count,
        )
        if any(value is not None for value in lookup_values):
            if self.receiver_method_owner_type is None or not self.receiver_method_owner_type.strip():
                raise ValueError("待解析返回方法的所属类型不能为空")
            if self.receiver_method_name is None or not self.receiver_method_name.strip():
                raise ValueError("待解析返回方法的名称不能为空")
            if self.receiver_method_argument_count is None:
                raise ValueError("待解析返回方法的参数个数不能为空")
            if self.receiver_method_argument_count < 0:
                raise ValueError("待解析返回方法的参数个数不能小于0")
