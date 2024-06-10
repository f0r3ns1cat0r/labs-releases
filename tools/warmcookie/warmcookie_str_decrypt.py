import idautils
import idc
import idaapi
import yara

from Crypto.Cipher import ARC4


class WarmCookie(object):
    KEY_OFFSET = 0x4
    KEY_SIZE = 0x4
    DATA_OFFSET = 0x8
    LOOKBACK_COUNT = 0xA

    WARMCOOKIE_YARA = """
    rule warmcookie_string_decryption {
        strings:
            $seq_str_decrypt = 
            { 
                48 89 5C 24 ??
                48 89 6C 24 ??
                48 89 74 24 ??
                57
                48 81 EC ?? ?? ?? ??
            }
        condition:
            1 of them
    }
    """

    RULES = yara.compile(source=WARMCOOKIE_YARA)

    @staticmethod
    def decrypt_string(encrypted_str: bytes, key: bytes) -> bytes:
        return ARC4.new(key).decrypt(encrypted_str)

    @staticmethod
    def get_xrefs(ea: int) -> list[int]:
        return [ref.frm for ref in idautils.XrefsTo(ea)]

    @staticmethod
    def set_decompiler_comment(address: int, decrypted_string: str) -> None:
        if not (cfunc := idaapi.decompile(address)):
            print(f"Failed to decompile function at: {hex(address)}")
            return

        tl = idaapi.treeloc_t()
        tl.ea = cfunc.get_eamap()[address][0].ea
        tl.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(tl, decrypted_string)
        cfunc.save_user_cmts()

    @staticmethod
    def get_string_decrypt_funcs() -> list[int]:
        result = list()
        text_seg = ida_segment.get_segm_by_name(".text")

        if not text_seg:
            return result

        matches = WarmCookie.RULES.match(
            data=idaapi.get_bytes(
                text_seg.start_ea, text_seg.end_ea - text_seg.start_ea
            )
        )

        for match in matches:
            print(f"Matched rule: {match.rule}")
            for offset in match.strings:
                result.append(text_seg.start_ea + offset[0])

        return result

    @staticmethod
    def get_encrypted_string(
        candidate_addrs: list[int],
    ) -> list[tuple[int, bytes, bytes]]:
        encrypted_strings = []
        for candidate_addr in candidate_addrs:
            lea_ea = candidate_addr
            for _ in range(WarmCookie.LOOKBACK_COUNT):
                lea_ea = idc.prev_head(lea_ea)
                if (
                    idc.print_insn_mnem(lea_ea) == "lea"
                    and idc.print_operand(lea_ea, 0) == "rcx"
                ):
                    break

            arg_ea = idc.get_operand_value(lea_ea, 1)

            if idc.is_loaded(arg_ea):
                size = idc.get_wide_dword(arg_ea)
                key = idc.get_bytes(arg_ea + WarmCookie.KEY_OFFSET, WarmCookie.KEY_SIZE)
                data = idc.get_bytes(arg_ea + WarmCookie.DATA_OFFSET, size)

                encrypted_strings.append((candidate_addr, key, data))

        return encrypted_strings

    @staticmethod
    def main():
        for func in WarmCookie.get_string_decrypt_funcs():
            for addr, key, encrypted_str in WarmCookie.get_encrypted_string(
                WarmCookie.get_xrefs(func)
            ):
                decrypted_str = WarmCookie.decrypt_string(encrypted_str, key)
                null_byte_count = decrypted_str.count(b"\x00")

                if null_byte_count > 1:
                    new_decrypted_str = decrypted_str.decode("utf-16")
                else:
                    new_decrypted_str = decrypted_str.decode("utf-8")

                print(hex(addr), new_decrypted_str)
                WarmCookie.set_decompiler_comment(addr, new_decrypted_str)


if __name__ == "__main__":
    WarmCookie.main()
