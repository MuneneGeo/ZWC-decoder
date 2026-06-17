#!/usr/bin/env python3
# ─────────────────────────────────────────────
#  Zero-Width Character Steganography Decoder
#  CTF Tool — works on any ZWC-encoded file
# ─────────────────────────────────────────────

import os
import sys

# ── Colours for terminal output ──────────────
GREEN  = '\033[92m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
RED    = '\033[91m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def banner():
    print(f"""
{CYAN}{BOLD}
 ███████╗██╗    ██╗ ██████╗    ██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗ 
 ╚══███╔╝██║    ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
   ███╔╝ ██║ █╗ ██║██║         ██║  ██║█████╗  ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
  ███╔╝  ██║███╗██║██║         ██║  ██║██╔══╝  ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
 ███████╗╚███╔███╔╝╚██████╗    ██████╔╝███████╗╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
 ╚══════╝ ╚══╝╚══╝  ╚═════╝    ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}        Zero-Width Character Steganography Decoder — CTF Edition{RESET}
""")

def get_file():
    """Prompt user for file path and validate it exists."""
    while True:
        path = input(f"{CYAN}[?] Enter file path: {RESET}").strip()
        if not path:
            print(f"{RED}[-] No file entered. Try again.{RESET}")
            continue
        if not os.path.exists(path):
            print(f"{RED}[-] File not found: {path}{RESET}")
            continue
        return path

def load_file(path):
    """Load file with UTF-8 encoding."""
    try:
        with open(path, encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        print(f"{RED}[-] Could not read as UTF-8. Try a different file.{RESET}")
        sys.exit(1)

def analyse(text):
    """Count and report all zero-width characters found."""
    counts = {
        0x200B: 0,   # ZWSP
        0x200C: 0,   # ZWNJ
        0x200D: 0,   # ZWJ
        0x2060: 0,   # Word Joiner
        0xFEFF: 0,   # BOM / Zero-Width No-Break Space
    }
    for ch in text:
        if ord(ch) in counts:
            counts[ord(ch)] += 1

    visible = ''.join(ch for ch in text if ord(ch) not in counts)
    total_hidden = sum(counts.values())

    print(f"\n{BOLD}── FILE ANALYSIS ─────────────────────────{RESET}")
    print(f"  Total characters : {len(text)}")
    print(f"  Visible text     : {len(visible)} chars → {repr(visible[:80])}")
    print(f"  Hidden chars     : {total_hidden}")
    print(f"\n  Breakdown:")
    names = {
        0x200B: 'ZWSP  U+200B (Zero-Width Space)',
        0x200C: 'ZWNJ  U+200C (Zero-Width Non-Joiner)',
        0x200D: 'ZWJ   U+200D (Zero-Width Joiner)',
        0x2060: 'WJ    U+2060 (Word Joiner)',
        0xFEFF: 'ZWNBS U+FEFF (BOM)',
    }
    found = {}
    for code, count in counts.items():
        if count > 0:
            print(f"    {names[code]}: {count}")
            found[code] = count

    return visible, found, total_hidden

def try_decode(text, zero_char, one_char, sep_char, bit_length):
    """
    Try to decode using given character assignments.
    Returns decoded string or None if nothing printable found.
    """
    segments = []
    current  = ''

    for ch in text:
        code = ord(ch)
        if sep_char and code == sep_char:
            if current:
                segments.append(current)
                current = ''
        elif code == one_char:
            current += '1'
        elif code == zero_char:
            current += '0'

    if current:
        segments.append(current)

    if not segments:
        return None

    # If no separator was used, split raw bits into chunks
    if not sep_char:
        raw_bits = ''.join(segments)
        segments = [raw_bits[i:i+bit_length]
                    for i in range(0, len(raw_bits), bit_length)
                    if len(raw_bits[i:i+bit_length]) == bit_length]

    decoded = ''
    for seg in segments:
        try:
            val = int(seg, 2)
            if 0 < val < 128:
                decoded += chr(val)
            else:
                decoded += '?'
        except ValueError:
            continue

    # Only return if result has meaningful printable content
    printable = sum(1 for c in decoded if c.isprintable() and c != '?')
    if printable / max(len(decoded), 1) > 0.6:
        return decoded
    return None

def decode_all_strategies(text, found_chars):
    """
    Try every common encoding strategy and report all results.
    Handles: different bit assignments, separators, bit lengths.
    """
    codes = list(found_chars.keys())
    results = []

    print(f"\n{BOLD}── TRYING ALL DECODE STRATEGIES ──────────{RESET}")

    # Common separator candidates
    sep_candidates = [0x200D, 0x2060, 0xFEFF, None]

    # Bit length candidates (7-bit ASCII or 8-bit)
    bit_lengths = [7, 8]

    attempt = 1
    seen = set()

    for sep in sep_candidates:
        remaining = [c for c in codes if c != sep]
        if len(remaining) < 2:
            # Only 1 type left — try as raw bitstream
            if not remaining:
                continue
            for bit_len in bit_lengths:
                result = try_decode(text, remaining[0], remaining[0], sep, bit_len)
                if result and result not in seen:
                    seen.add(result)
                    results.append((f"Strategy {attempt}", result))
                    print(f"  {GREEN}[+] Strategy {attempt}{RESET}: sep=U+{sep:04X} if sep else 'none', bits={bit_len}")
                    print(f"      Result: {YELLOW}{result}{RESET}")
                attempt += 1
            continue

        # Try both assignments of the two remaining chars as 0 and 1
        for zero_c, one_c in [(remaining[0], remaining[1]),
                               (remaining[1], remaining[0])]:
            for bit_len in bit_lengths:
                result = try_decode(text, zero_c, one_c, sep, bit_len)
                if result and result not in seen:
                    seen.add(result)
                    results.append((f"Strategy {attempt}", result))
                    sep_label = f"U+{sep:04X}" if sep else "none"
                    print(f"  {GREEN}[+] Strategy {attempt}{RESET}: "
                          f"0=U+{zero_c:04X}, 1=U+{one_c:04X}, "
                          f"sep={sep_label}, bits={bit_len}")
                    print(f"      Result: {YELLOW}{result}{RESET}")
                attempt += 1

    return results

def pick_flag(results):
    """Ask user to identify which result is the flag."""
    if not results:
        print(f"\n{RED}[-] No readable hidden message found.{RESET}")
        print(f"    The file may use a non-standard encoding.")
        return

    if len(results) == 1:
        print(f"\n{GREEN}{BOLD}🚩 HIDDEN MESSAGE: {results[0][1]}{RESET}")
        return

    print(f"\n{BOLD}── RESULTS SUMMARY ───────────────────────{RESET}")
    for i, (label, result) in enumerate(results, 1):
        print(f"  [{i}] {result}")

    print(f"\n{CYAN}[?] Which result looks like the flag? (enter number, or 0 to show all){RESET}")
    while True:
        try:
            choice = int(input(f"{CYAN}>>> {RESET}").strip())
            if choice == 0:
                for label, result in results:
                    print(f"  {GREEN}🚩 {result}{RESET}")
                break
            elif 1 <= choice <= len(results):
                print(f"\n{GREEN}{BOLD}🚩 FLAG: {results[choice-1][1]}{RESET}")
                break
            else:
                print(f"{RED}Invalid choice.{RESET}")
        except ValueError:
            print(f"{RED}Enter a number.{RESET}")

def save_results(results):
    """Optionally save results to a file."""
    answer = input(f"\n{CYAN}[?] Save results to file? (y/n): {RESET}").strip().lower()
    if answer == 'y':
        out = 'zwc_results.txt'
        with open(out, 'w') as f:
            for label, result in results:
                f.write(f"{label}: {result}\n")
        print(f"{GREEN}[+] Saved to {out}{RESET}")

def main():
    banner()

    # ── 1. Get file ──────────────────────────
    path = get_file()
    print(f"{GREEN}[+] Loaded: {path}{RESET}")

    # ── 2. Read it ───────────────────────────
    text = load_file(path)

    # ── 3. Analyse ───────────────────────────
    visible, found_chars, total_hidden = analyse(text)

    if total_hidden == 0:
        print(f"\n{RED}[-] No zero-width characters found in this file.{RESET}")
        print(f"    This file may not use ZWC steganography.")
        sys.exit(0)

    print(f"\n{GREEN}[+] Hidden characters detected! Starting decode...{RESET}")

    # ── 4. Try all strategies ─────────────────
    results = decode_all_strategies(text, found_chars)

    # ── 5. Present flag ───────────────────────
    pick_flag(results)

    # ── 6. Optionally save ────────────────────
    if results:
        save_results(results)

    print(f"\n{CYAN}── Done ───────────────────────────────────{RESET}\n")

if __name__ == '__main__':
    main()
