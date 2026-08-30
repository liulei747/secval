"""为关键词搜索切分代码和查询文本。"""

import re


# 找出英文标识符、独立数字和连续中文文本。
TEXT_PART_PATTERN = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[\u4e00-\u9fff]+"
)

# 把 camelCase、PascalCase 和全大写缩写拆成组成词。
IDENTIFIER_PART_PATTERN = re.compile(
    r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[A-Z]+|[0-9]+"
)


def tokenize_code(text: str) -> list[str]:
    """返回适合关键词搜索的词列表。"""

    tokens: list[str] = []
    text_parts = TEXT_PART_PATTERN.findall(text)

    for text_part in text_parts:
        if _is_english_identifier(text_part):
            identifier_tokens = _split_identifier(text_part)
            tokens.extend(identifier_tokens)
        else:
            tokens.append(text_part.lower())

    return tokens


def _is_english_identifier(text: str) -> bool:
    """判断文本是否是需要进一步拆分的英文标识符。"""

    first_character = text[0]
    return first_character.isascii() and (
        first_character.isalpha() or first_character == "_"
    )


def _split_identifier(identifier: str) -> list[str]:
    """保留完整标识符，并拆分下划线和大小写组成词。"""

    tokens: list[str] = []
    normalized_identifier = identifier.lower()
    tokens.append(normalized_identifier)

    underscore_parts = identifier.split("_")

    for underscore_part in underscore_parts:
        if not underscore_part:
            continue

        identifier_parts = IDENTIFIER_PART_PATTERN.findall(underscore_part)

        for identifier_part in identifier_parts:
            normalized_part = identifier_part.lower()

            # 简单标识符的完整形式和拆分结果相同，不重复加入。
            if normalized_part != normalized_identifier:
                tokens.append(normalized_part)

    return tokens

