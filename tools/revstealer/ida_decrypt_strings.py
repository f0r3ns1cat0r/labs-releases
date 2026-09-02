import idaapi
import ida_segment
import ida_nalt
import os
import yara


from nightMARE.malware.revstealer.strings import decrypt_strings


class RevStealer(object):
    REVSTEALER_YARA = """
    rule revstealer_string_decryption {
        strings:
            $seq_str_decrypt_ascii = 
            { 
                 664489442418488954241048894C24084883EC1848C74424 
            }
            $seq_str_decrypt_wide =  
            { 
                664489442418488954241048894C24084883EC2848C74424
            }
            
        condition:
            any of them
    }
    """

    RULES = yara.compile(source=REVSTEALER_YARA)

    @staticmethod
    def set_decompiler_comment(address: int, decrypted_string: str) -> None:
        if not (cfunc := idaapi.decompile(address)):
            print(f"  [!] Failed to decompile function at: {hex(address)}")
            return

        eamap = cfunc.get_eamap()
        if address not in eamap:
            print(f"  [!] {hex(address)} not in eamap")
            return

        tl = idaapi.treeloc_t()
        tl.ea = eamap[address][0].ea
        tl.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(tl, decrypted_string)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        print(f"  [+] Comment set at {hex(address)}: {decrypted_string}")

    @staticmethod
    def get_string_decrypt_funcs() -> list[int]:
        result = list()
        seg_ea = ida_segment.get_segment_ea_by_name(".text")
        if seg_ea == idaapi.BADADDR:
            return result
        text_seg = ida_segment.segment_info_t()
        if not ida_segment.get_segment_info(text_seg, seg_ea):
            return result

        matches = RevStealer.RULES.match(
            data=idaapi.get_bytes(
                text_seg.start_ea, text_seg.end_ea - text_seg.start_ea
            )
        )

        for match in matches:
            print(f"Matched rule: {match.rule}")
            for string_match in match.strings:
                is_wide = "wide" in string_match.identifier
                for instance in string_match.instances:
                    result.append((text_seg.start_ea + instance.offset, is_wide))

        return result

    @staticmethod
    def main():
        input_path = ida_nalt.get_input_file_path()
        if not input_path or not os.path.exists(input_path):
            input_path = idaapi.ask_file(
                False, "*.exe;*.dll;*.bin", "Select binary to analyze"
            )
            if not input_path:
                print("[!] No binary selected.")
                return

        binary = open(input_path, "rb").read()

        funcs = RevStealer.get_string_decrypt_funcs()
        if not funcs:
            print(
                "[!] No RevStealer string decryption functions found — check YARA signature or use unpacked sample."
            )
            return

        results = {}
        for func, is_wide in funcs:
            print(
                f"[*] Processing decryption function at {func:#x} ({'wide' if is_wide else 'ascii'})"
            )
            for xref, decrypted in decrypt_strings(binary, func, wide=is_wide).items():
                decrypted_str = decrypted.decode("utf-8", errors="ignore")
                if not decrypted_str and decrypted:
                    decrypted_str = f"<{decrypted.hex()}>"
                results[xref] = decrypted_str

        print("\n=== Decrypted Strings ===")
        for xref, s in sorted(results.items()):
            print(f"  {xref:#x}: {s}")

        print("\n=== Applying Comments ===")
        for xref, s in results.items():
            try:
                RevStealer.set_decompiler_comment(xref, s)
            except Exception as e:
                print(f"  [!] Failed at {xref:#x}: {e}")


if __name__ == "__main__":
    RevStealer.main()
