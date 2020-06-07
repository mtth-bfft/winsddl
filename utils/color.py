import ctypes
import platform
import re

global_counter = 0

COLORS = [31,32,34,35,36] #41,42,43,44,45,46,54]


def colorize(s: str) -> str:
    global global_counter
    global_counter += 1
    if global_counter == 1 and platform.system() == 'Windows':
        k = ctypes.windll.kernel32
        mode = ctypes.c_uint32(0)
        k.GetConsoleMode(k.GetStdHandle(-11), ctypes.byref(mode))
        k.SetConsoleMode(k.GetStdHandle(-11), mode.value | 0x4)  # enable virtual terminal processing

    color = COLORS[global_counter % len(COLORS)]
    start = f"\033[;1;{color}m"
    end = "\033[;0;0m"
    return start + s + end


def propagate_colors(dense: str, colored: str) -> str:
    pos_in_dense = 0
    for colored_part, text_part in re.findall(r'(\033\[;1;[0-9]+m(.+?)\033\[;0;0m)', colored):
        text_pos = dense.find(text_part, pos_in_dense)
        if text_pos < 0:
            break
        dense = dense[:text_pos] + colored_part + dense[text_pos + len(text_part):]
        pos_in_dense = text_pos + len(colored_part)
    return dense
