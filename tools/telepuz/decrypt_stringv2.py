# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

# coding: utf-8

import idc
import ida_idd
import idautils
import ida_bytes
import string


def apply_patches(patches: dict[int, bytes]):
    for k, v in patches:
        ida_bytes.patch_bytes(k, v)
        ida_bytes.create_strlit(k, 0, 0)


def dbg_decrypt_strings(decryption_function_address: int) -> dict[int, bytes]:
    decrypt = ida_idd.Appcall.proto(
        decryption_function_address,
        "char *__fastcall Decrypt(uint8_t *p_key, uint8_t *p_encrypted, uint8_t *p_decrypted, BOOL *p_is_decrypted, uint32_t data_size);",
    )

    results = {}
    for xref in idautils.XrefsTo(decryption_function_address):
        print(f"[*] Decrypting at {xref.frm:x}")
        try:
            key, encrypted, decrypted_ea, is_decrypted_ea = get_decryption_parameters(
                xref.frm
            )
            results[decrypted_ea] = bytes(
                [
                    x
                    for x in decrypt(
                        key, encrypted, decrypted_ea, is_decrypted_ea, len(encrypted)
                    )
                    if x in string.printable.encode("utf-8")
                ]
            )
            print(f"[+] Success at {xref.frm:x}")
        except Exception:
            print(f"[-] Failed at {xref.frm:x}")
            continue
    return results


def get_bytes_until_next_item(address: int) -> bytes:
    return ida_bytes.get_bytes(address, get_next_item(address) - address)


def get_decryption_parameters(start: int) -> tuple[bytes, bytes, int]:
    parameters = {"rcx": 0, "rdx": 0, "r8": 0, "r9": 0}

    ea = start
    tries = 100
    while not all(parameters.values()) and tries:
        tries -= 1
        ea = idc.prev_head(ea)
        if "lea" == idc.print_insn_mnem(ea):
            reg = idc.print_operand(ea, 0)
            if parameters.get(reg, None) is not None:
                parameters[reg] = idc.get_operand_value(ea, 1)

    if not tries:
        raise RuntimeError("Failed to recover parameters")

    key = get_bytes_until_next_item(parameters["rcx"])
    encrypted = get_bytes_until_next_item(parameters["rdx"])
    decrypted = parameters["r8"]
    is_decrypted = parameters["r9"]

    return key, encrypted, decrypted, is_decrypted


def get_next_item(item_ea: int) -> int:
    i = 1
    while not list(idautils.XrefsTo(item_ea + i)):
        i += 1
    return item_ea + i


if __name__ == "__main__":
    print("== Instructions ==")
    print("1. Find the string decryption function's address")
    print("2. Start the malware in a debugger and pause it on any breakpoint")
    print(
        "3. In the IDAPython console: x = dbg_decrypt_strings(decryption_function_address)"
    )
    print(
        "4. Stop the debugger and optionally patch the idb with the results: apply_patches(x)"
    )
    print()
