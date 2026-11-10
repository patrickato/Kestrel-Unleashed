"""Tests for the John the Ripper on-device engine (kestrel_pi.crack.john).

No John binary needed: the hc22000->John/hccapx conversions are verified against
synthesized known-password handshakes (the same vectors proven end to end against
a real john jumbo), and the --show / progress parsers against canned John output.
"""

import hashlib
import hmac
import struct

from kestrel_pi.crack import john


# --- vector synthesis (pure crypto; deterministic) --------------------------
def _pmkid_line(psk="password123", essid="TestNet",
                ap="aabbccddeeff", sta="112233445566"):
    mac_ap, mac_sta = bytes.fromhex(ap), bytes.fromhex(sta)
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), essid.encode(), 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + mac_ap + mac_sta, hashlib.sha1).digest()[:16]
    return ("WPA*01*%s*%s*%s*%s***" % (pmkid.hex(), ap, sta, essid.encode().hex()),
            pmkid.hex())


def _eapol_line(psk="password123", essid="TestNet",
                ap="aabbccddeeff", sta="112233445566"):
    AA, SPA = bytes.fromhex(ap), bytes.fromhex(sta)
    anonce, snonce = bytes.fromhex("11" * 32), bytes.fromhex("22" * 32)

    def prf(key, label, data, n):
        out, i = b"", 0
        while len(out) < n:
            out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
            i += 1
        return out[:n]

    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), essid.encode(), 4096, 32)
    kck = prf(pmk, b"Pairwise key expansion",
              min(AA, SPA) + max(AA, SPA) + min(anonce, snonce) + max(anonce, snonce), 48)[:16]
    body = (b"\x02" + b"\x01\x0a" + b"\x00\x00" + (1).to_bytes(8, "big")
            + snonce + b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8 + b"\x00" * 16 + b"\x00\x00")
    frame = b"\x02\x03" + struct.pack(">H", len(body)) + body
    mic = hmac.new(kck, frame, hashlib.sha1).digest()[:16]
    line = "WPA*02*%s*%s*%s*%s*%s*%s*00" % (mic.hex(), ap, sta,
            essid.encode().hex(), anonce.hex(), frame.hex())
    return line, snonce


# --- PMKID conversion -------------------------------------------------------
def test_pmkid_to_john_reshuffles_fields():
    line, pmkid = _pmkid_line()
    out = john.pmkid_to_john(line)
    assert out == ("TestNet:%s*aabbccddeeff*112233445566*%s"
                   ":112233445566:aabbccddeeff:aabbccddeeff::PMKID:kestrel"
                   % (pmkid, "TestNet".encode().hex()))
    assert john.pmkid_to_john("WPA*02*...*..*..*..*..*..*00") is None   # EAPOL, not PMKID
    assert john.pmkid_to_john("garbage") is None


# --- EAPOL conversion -------------------------------------------------------
def test_eapol_to_hccapx_builds_a_valid_record():
    line, snonce = _eapol_line()
    rec = john.eapol_to_hccapx(line)
    assert rec is not None and len(rec) == john.HCCAPX_SIZE
    assert rec[:4] == b"HCPX" and struct.unpack("<I", rec[4:8])[0] == 4
    essid_len = rec[9]
    assert rec[10:10 + essid_len] == b"TestNet"
    keyver = rec[42]
    assert keyver == 2                                   # WPA2 from the key-info bits
    # the STA nonce must be the one pulled out of the EAPOL frame
    # layout: …mic[43:59] ap[59:65] anonce[65:97] sta[97:103] snonce[103:135]
    sta_nonce = rec[103:135]
    assert sta_nonce == snonce
    assert john.eapol_to_hccapx("WPA*01*x*y*z*w***") is None   # PMKID, not EAPOL


def test_split_sources_separates_pmkid_and_eapol():
    pmkid_line, _ = _pmkid_line()
    eapol_line, _ = _eapol_line(ap="001122334455")
    pmkids, blob = john.split_sources([pmkid_line, eapol_line, "junk", ""])
    assert len(pmkids) == 1 and pmkids[0].startswith("TestNet:")
    assert len(blob) == john.HCCAPX_SIZE                 # one EAPOL record packed


# --- command lines ----------------------------------------------------------
def test_build_crack_cmd_and_show_cmd():
    cmd = john.build_crack_cmd("/h.john", "/rockyou.txt", "/p.pot",
                               rules="best64", progress_every=2)
    assert "--format=wpapsk" in cmd and "--wordlist=/rockyou.txt" in cmd
    assert "--rules=best64" in cmd and "--pot=/p.pot" in cmd
    assert "--progress-every=2" in cmd and cmd[-1] == "/h.john"
    show = john.build_show_cmd("/h.john", "/p.pot")
    assert show[:2] == ["john", "--show"] and show[-1] == "/h.john"


# --- --show parsing ---------------------------------------------------------
def test_parse_show_maps_bssid_essid_password():
    pmkid = "TestNet:password123:112233445566:aabbccddeeff:aabbccddeeff::PMKID:kestrel"
    eapol = ("HomeNet:hunter2:665544332211:001122334455:001122334455::"
             "WPA2:not verified:/tmp/x.hccapx")
    got = john.parse_show(pmkid + "\n" + eapol + "\n\n")
    assert ("AA:BB:CC:DD:EE:FF", "TestNet", "password123") in got
    assert ("00:11:22:33:44:55", "HomeNet", "hunter2") in got


def test_parse_show_keeps_colon_passwords():
    line = "Cafe:pa:ss:word:112233445566:aabbccddeeff:aabbccddeeff::PMKID:kestrel"
    got = john.parse_show(line)
    assert got == [("AA:BB:CC:DD:EE:FF", "Cafe", "pa:ss:word")]


# --- progress parsing -------------------------------------------------------
def test_parse_progress_reads_johns_status_line():
    line = ("0g 0:00:00:02 0.03% (ETA: 20:10:43) 0g/s 13359p/s 13359c/s "
            "13359C/s 12842111..49542111")
    p = john.parse_progress(line)
    assert p["percent"] == 0.03
    assert abs(p["rate_kps"] - 13.359) < 1e-6           # p/s shown as k/s
    assert p["eta"] == "20:10:43"
    assert p["passphrase"] == "49542111"


def test_parse_progress_done_line_and_empty():
    done = ("1g 0:00:00:00 DONE (2026-11-10 18:11) 12.50g/s 25.00p/s 25.00c/s "
            "825.0C/s wrongpass..password123")
    p = john.parse_progress(done)
    assert p.get("passphrase") == "password123" and "percent" not in p
    assert abs(p["rate_kps"] - 0.025) < 1e-9
    assert john.parse_progress("") == {}
    assert john.parse_progress("Loaded 3 password hashes\n") == {}


def test_have_john_is_a_bool():
    assert isinstance(john.have_john(), bool)


# --- mask support -----------------------------------------------------------
def test_mask_to_john_passes_safe_classes_and_rejects_others():
    assert john.mask_to_john("?d?d?d?d?d?d?d?d") == "?d?d?d?d?d?d?d?d"
    assert john.mask_to_john("?l?u?d?s") == "?l?u?d?s"
    assert john.mask_to_john("?H?H") is None          # hex class John can't share
    assert john.mask_to_john("abc?d") is None          # literals present
    assert john.mask_to_john("") is None


def test_build_mask_cmd():
    cmd = john.build_mask_cmd("/h.john", "?d?d?d?d", "/p.pot")
    assert "--mask=?d?d?d?d" in cmd and "--format=wpapsk" in cmd
    assert "--pot=/p.pot" in cmd and cmd[-1] == "/h.john"
