"""把可选原文件行号转换成字符区间，结束行包含在内。"""


def validate_line_range(arguments):
    supplied = {key for key in ("start_line", "end_line") if key in arguments}
    if not supplied:
        return
    if "char_offset" in arguments:
        raise ValueError("行号范围不能与char_offset同时使用")
    for key in supplied:
        if type(arguments[key]) is not int or arguments[key] < 1:
            raise ValueError("行号必须是从1开始的整数")
    if len(supplied) == 2 and arguments["start_line"] > arguments["end_line"]:
        raise ValueError("开始行不能大于结束行")


def source_range(content, arguments, base_line=1):
    validate_line_range(arguments)
    if "start_line" not in arguments and "end_line" not in arguments:
        offset = arguments.get("char_offset", 0)
        if not content or offset >= len(content):
            raise ValueError("读取偏移超出正文范围")
        return offset, min(offset + 12000, len(content)), False
    starts = [0] + [i + 1 for i, char in enumerate(content) if char == "\n" and i + 1 < len(content)]
    last_line = base_line + len(starts) - 1
    start = arguments.get("start_line", base_line)
    end = arguments.get("end_line", last_line)
    if not content or start < base_line or end > last_line or start > end:
        raise ValueError("行号超出当前源码范围")
    offset = starts[start - base_line]
    stop = starts[end - base_line + 1] if end < last_line else len(content)
    if stop - offset > 12000:
        raise ValueError("所选行范围超过12000字符，请缩小行范围或改用char_offset续读")
    return offset, stop, True
