"""单个源文件处理失败的数据模型。"""

from dataclasses import dataclass


@dataclass
class FileProcessError:
    """记录处理失败的文件路径和原因。"""

    relative_path: str
    message: str

    def __post_init__(self) -> None:
        """创建对象时检查错误信息。"""

        if not self.relative_path.strip():
            raise ValueError("失败文件的相对路径不能为空")

        if not self.message.strip():
            raise ValueError("文件处理错误信息不能为空")

