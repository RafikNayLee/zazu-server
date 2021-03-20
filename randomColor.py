from random import choice

hex_chars = ['0','1','2','3','4','5','6','7','8','9','a','b','c', 'd', 'e', 'f']

def getRandomColor():
    color_code = "#"
    for i in range(6):
        color_code = color_code + choice(hex_chars)

    return color_code