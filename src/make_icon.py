"""Build-time tool: generates tor_rotator.ico (exe/tray icon) and assets/icon.png (README)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tor_rotator_tray import draw_icon

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    img = draw_icon(256)
    ico_path = os.path.join(HERE, 'tor_rotator.ico')
    img.save(ico_path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print('wrote', ico_path)
    png_path = os.path.join(HERE, '..', 'assets', 'icon.png')
    draw_icon(512).save(png_path)
    print('wrote', os.path.abspath(png_path))

if __name__ == '__main__':
    main()
