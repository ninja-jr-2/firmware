import os
import re
import glob

print("Patching ESP8266SAM to fix yield() conflict...")

lib_pattern = ".pio/libdeps/*/ESP8266SAM/src/render.c"
files = glob.glob(lib_pattern)

for file_path in files:
    try:
        with open(file_path, 'r') as file:
            content = file.read()

        if 'static void sam_yield' in content:
            print(f"Already patched: {file_path}")
            continue

        content = re.sub(r'static void yield\(\)', 'static void sam_yield()', content)
        content = re.sub(r'\byield\(\);', 'sam_yield();', content)

        with open(file_path, 'w') as file:
            file.write(content)
        print(f"Patched: {file_path}")
    except Exception as e:
        print(f"Failed to patch {file_path}: {e}")
