import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
import json

class OneMnemonicAnyOpcode:
    
    def run(self, args, **kargs):
        """Wrap subprocess.run to works on Windows and Linux"""
        # Windows needs shell to be True, to locate binary automatically
        # On Linux, shell needs to be False to manage lists in args
        shell = sys.platform in ["win32"]
        return subprocess.run(args, shell=shell, **kargs)
    
    def get_asm_mnemonic(self, opcode: int):
        asm_code = self.run(
                [
                    'rasm2', 
                    '-d', 
                    f'{opcode:x}'
                ], capture_output=True)
        print(opcode)
        if b'WARN: Invalid hexpair string' not in asm_code.stderr and b'invalid' not in asm_code.stdout:
            return [asm_code.stdout.replace(b'\r\n', b'').decode("utf-8"), f'0x{opcode:x}']
        else:
            return None
    
    def find_equals(self, opcode_max_len: int):
        # map
        with ThreadPoolExecutor(max_workers = 100) as executor:
            thread_pool = executor.map(
                self.get_asm_mnemonic, 
                [i for i in range(0, 256**opcode_max_len-1)]
            )

        # reduce
        # clean None values from result and collect opcodes for mnemonics
        first_data = {}
        for thread_data in thread_pool:
            if thread_data is not None:
                if thread_data[0] not in first_data:
                    first_data[thread_data[0]] = [thread_data[1]]
                else:
                    first_data[thread_data[0]].append(thread_data[1])
        # clean single opcode mnemonic
        for k in list(first_data.keys()):
            if len(first_data[k]) < 2:
                del first_data[k]

        # write result
        with open('result.json', 'w') as file:
            file.write(json.dumps(first_data))
    
    def __init__(self):
        pass

if __name__ == "__main__":
    instance = OneMnemonicAnyOpcode()
    instance.find_equals(2)
