"""Product choices admitted by this release, independent of any transport."""
from __future__ import annotations

import math
import re
import unicodedata
from typing import Any


class PolicyError(ValueError):
    pass


RECIPES = ("st", "m9")
_ICON = re.compile(r"(?:[A-Za-z0-9]{1,3}|[\u3400-\u4dbf\u4e00-\u9fff\U00020000-\U0002ee5f\U00030000-\U000323af])\Z")


def display_name(value):
    if (type(value) is not str or not value.strip() or not 1<=len(value)<=32
            or any(unicodedata.category(c)=='Cc' for c in value)):
        raise PolicyError('显示名称须为1–32个可显示字符，不得为空白或含控制字符。')
    try:size=len(value.encode('utf-8'))
    except UnicodeError:raise PolicyError('显示名称必须是有效UTF-8文字。') from None
    if size>63:raise PolicyError('显示名称的UTF-8编码不得超过63字节；不会截断。')
    return value


def filter_selection(value: Any) -> dict:
    """Validate four fixed runtime positions; never import a LUT/CUBE path.

    ST means preserve the current color recipe; it never erases an existing preset. Names and icons do not identify a recipe.
    Excluding a slot from this operation never renumbers the other positions.
    Actual native glyph support remains the native icon renderer's decision.
    """
    fields = {"schema", "include_fl2", "include_fl3", "st_notice_accepted", "slots"}
    if not isinstance(value, dict) or set(value) != fields:
        raise PolicyError("滤镜配置字段不符；本版不接受滤镜文件或上传路径。")
    if value["schema"] != "a7m4-toolbox-filters/1":
        raise PolicyError("不支持的滤镜配置版本。")
    for key in ("include_fl2", "include_fl3", "st_notice_accepted"):
        if type(value[key]) is not bool:
            raise PolicyError("FL2、FL3 和 ST 须知必须明确选择。")
    if value["st_notice_accepted"] is not True:
        raise PolicyError("请先确认所使用的自定义位置以 ST 为基底。")
    slots = value["slots"]
    if not isinstance(slots, list) or len(slots) != 4:
        raise PolicyError("必须保留固定的四个自定义位置。")
    result = []
    slot_fields = {"slot", "selected", "recipe", "name", "icon_text"}
    for expected, item in enumerate(slots, 1):
        if not isinstance(item, dict) or set(item) != slot_fields:
            raise PolicyError("位置字段不符；不接受 CUBE、其他配方或隐藏上传路径。")
        if type(item["slot"]) is not int or item["slot"] != expected:
            raise PolicyError("位置必须按 1–4 固定编号，不可重复或压缩重排。")
        if type(item["selected"]) is not bool or item["recipe"] not in RECIPES:
            raise PolicyError("本版自定义滤镜仅提供内置 M9；可保留 ST 基底。")
        if item["recipe"] == "m9" and expected != 1:
            raise PolicyError("本版 M9 安装目标固定为自定义位置 1／ST；其他位置保持原样。")
        name = display_name(item["name"])
        if not isinstance(item["icon_text"], str) or not _ICON.fullmatch(item["icon_text"]):
            raise PolicyError("图标文字限 1–3 个英文字母或数字，或一个受支持的汉字。")
        result.append(dict(item))
    return {**value, "slots": result}


def sound_state(value: Any) -> str:
    if type(value) is not str or value not in ("enabled", "disabled"):
        raise PolicyError("电子快门声状态必须为 enabled 或 disabled；静音增益不能替代开关。")
    return value


def gain_db(value: Any) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not -36 <= value <= 6:
        raise PolicyError("生成音量须为 -36 至 +6 dB 的有限数值。")
    return float(value)
