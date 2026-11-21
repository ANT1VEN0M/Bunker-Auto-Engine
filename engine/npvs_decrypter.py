import base64
import hashlib
import json
import struct
import urllib.parse
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from engine.link_builder import extract_links_from_json, item_to_links
    from engine.whitebox_aes import NPVTDecrypter
except ImportError:
    from link_builder import extract_links_from_json, item_to_links
    from whitebox_aes import NPVTDecrypter

SHIFT_ORDER = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
NPV_SENTINEL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"


def decode_sentinel_token(tok: str) -> Optional[str]:
    for pad in ("", "=", "==", "==="):
        t = tok + pad
        for alt in (None, "-_"):
            try:
                b = base64.b64decode(t, altchars=alt)
                return b.decode("utf-8", errors="replace")
            except Exception:
                pass
    return None


def decode_sentinels(s: str) -> str:
    if not isinstance(s, str):
        return s
    prefix = "npvs1:"
    out = []
    while prefix in s:
        before, s = s.split(prefix, 1)
        out.append(before)
        j = 0
        while j < len(s) and s[j] in NPV_SENTINEL_ALPHABET:
            j += 1
        tok = s[:j]
        s = s[j:]
        dec = decode_sentinel_token(tok)
        if dec is not None:
            out.append(dec)
        else:
            out.append(prefix + tok)
    out.append(s)
    return "".join(out)


def walk_decode_sentinels(v: Any) -> Any:
    if isinstance(v, str):
        return decode_sentinels(v)
    elif isinstance(v, dict):
        return {k: walk_decode_sentinels(val) for k, val in v.items()}
    elif isinstance(v, list):
        return [walk_decode_sentinels(val) for val in v]
    return v


def b64url_decode(s: str) -> bytes:
    s = s.strip()
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return base64.b64decode(s)


class NPVSDecrypter:
    def __init__(self, tables_dict: Dict[str, Any], gen2_tables_path: Optional[str] = None):
        self.tables_dict = tables_dict
        self.wb_aes = NPVTDecrypter(tables_dict)
        self.tlast_variants = []

        # Variant 1 (if available in tables or data)
        if "tboxesLastV1" in tables_dict and "data" in tables_dict["tboxesLastV1"]:
            self.tlast_variants.append(tables_dict["tboxesLastV1"]["data"])

        # Check data directory for tboxes_last_v1.bin if not in dict
        data_dir = Path(__file__).resolve().parent
        v1_path = data_dir / "tboxes_last_v1.bin"
        if not self.tlast_variants and v1_path.exists():
            try:
                with open(v1_path, "rb") as f:
                    self.tlast_variants.append(list(f.read()))
            except Exception:
                pass

        # Variant 2 (from npv_tables.json tboxesLast)
        if "tboxesLast" in tables_dict and "data" in tables_dict["tboxesLast"]:
            self.tlast_variants.append(tables_dict["tboxesLast"]["data"])

        # Path for Gen2 tables
        if gen2_tables_path:
            self.gen2_tables_path = Path(gen2_tables_path)
        else:
            self.gen2_tables_path = data_dir / "gen2_tables.bin.z"

        self._gen2_tables: Optional[bytes] = None

    def _get_gen2_tables(self) -> bytes:
        if self._gen2_tables is not None:
            return self._gen2_tables

        if not self.gen2_tables_path.exists():
            raise FileNotFoundError(
                f"Gen2 tables not found at {self.gen2_tables_path}. "
                "Please ensure data/gen2_tables.bin.z exists."
            )

        with open(self.gen2_tables_path, "rb") as f:
            compressed = f.read()

        decompressed = zlib.decompress(compressed)
        expected_size = 13 * 57344 + 4096
        if len(decompressed) != expected_size:
            raise ValueError(
                f"gen2 tables have wrong size: got {len(decompressed)}, want {expected_size}"
            )
        self._gen2_tables = decompressed
        return self._gen2_tables

    def decrypt(self, raw_input: Union[bytes, str], password: str = "") -> Dict[str, Any]:
        """
        Decrypts an NPVS input (can be bytes or string, Open/v1/v5 format).
        Returns:
            {
                "links": list of config links,
                "raw_blocks": list of (index, raw_string),
                "creator_message": str,
                "metadata": dict or None
            }
        """
        data_bytes, text_repr = self._normalize_input(raw_input)

        # Check Open format (starts with NPVO1)
        if text_repr and text_repr.lstrip().startswith("NPVO1"):
            return self._decrypt_open(text_repr)

        # Check Gen2 / v5 format
        if len(data_bytes) >= 9 and data_bytes[:4] == b"NPVS" and data_bytes[4] == 5:
            return self._decrypt_gen2(data_bytes, password)

        # Check Gen1 binary format (v <= 1)
        if len(data_bytes) >= 9 and data_bytes[:4] == b"NPVS" and data_bytes[4] <= 1:
            return self._decrypt_v1(data_bytes, password)

        # Fallback check: could it be plain JSON or sentinels?
        if text_repr and (text_repr.lstrip().startswith("{") or text_repr.lstrip().startswith("[")):
            decoded_text = decode_sentinels(text_repr)
            try:
                obj = json.loads(decoded_text)
                obj = walk_decode_sentinels(obj)
                links = self._extract_all_links(obj)
                return {
                    "links": links,
                    "raw_blocks": [(0, json.dumps(obj, ensure_ascii=False, indent=2))] if not links else [],
                    "creator_message": "",
                    "metadata": None,
                }
            except Exception:
                pass

        raise ValueError("داده ورودی با فرمت معتبر NPVS همخوانی ندارد.")

    def _normalize_input(self, raw_input: Union[bytes, str]) -> Tuple[bytes, Optional[str]]:
        if isinstance(raw_input, bytes):
            # Check if it starts with text like NPVO1 or base64
            try:
                text = raw_input.decode("utf-8")
                # Try decoding base64 if it might be base64-encoded binary NPVS
                clean_text = "".join(text.split())
                if clean_text.startswith("TlBWUw"):  # base64 for NPVS
                    try:
                        b = base64.b64decode(clean_text)
                        return b, text
                    except Exception:
                        pass
                return raw_input, text
            except UnicodeDecodeError:
                return raw_input, None
        else:
            text = raw_input.strip()
            # If it's NPVO1 text
            if text.startswith("NPVO1"):
                return text.encode("utf-8"), text

            # Check if it's base64 encoded
            clean = "".join(text.split())
            try:
                b = base64.b64decode(clean)
                if len(b) >= 4 and b[:4] == b"NPVS":
                    return b, text
            except Exception:
                pass

            return text.encode("utf-8", errors="ignore"), text

    def _decrypt_open(self, text: str) -> Dict[str, Any]:
        body = text.replace("NPVO1\n", "").replace("NPVO1", "").strip()
        if not body:
            raise ValueError("فایل NPVO1 خالی است.")

        obj = json.loads(body)
        obj = walk_decode_sentinels(obj)
        configs = obj.get("configs", [])
        if not configs and isinstance(obj, list):
            configs = obj

        links = []
        for cfg in configs:
            link = self._config_to_link(cfg)
            if link:
                links.append(link)

        if not links:
            links = extract_links_from_json(configs)

        return {
            "links": links,
            "raw_blocks": [(0, json.dumps(obj, ensure_ascii=False, indent=2))] if not links else [],
            "creator_message": "",
            "metadata": None,
        }

    def _decrypt_v1(self, data: bytes, password: str = "") -> Dict[str, Any]:
        hdr_len = struct.unpack(">I", data[5:9])[0]
        if 9 + hdr_len > len(data):
            raise ValueError("طول هدر نامعتبر است.")

        hdr_raw = data[9 : 9 + hdr_len]
        hdr = json.loads(hdr_raw.decode("utf-8"))

        off = 9 + hdr_len
        if off + 16 > len(data):
            raise ValueError("بخش بدنه ناقص است.")

        nonce = data[off : off + 12]
        body_len = struct.unpack(">I", data[off + 12 : off + 16])[0]
        off += 16
        if off + body_len > len(data):
            raise ValueError("طول بدنه نامعتبر است.")

        body_ct_tag = data[off : off + body_len]

        # Policy & messages
        policy = hdr.get("policy", {}) or {}
        msg_parts = [
            m.strip().replace("\r\n", "\n")
            for m in [policy.get("displayMessage"), policy.get("customServerMessage")]
            if m and m.strip()
        ]
        creator_message = "\n".join(msg_parts)

        # Derive DEK
        dek = None
        app_key = hdr.get("appKey")
        passphrase_wrap = hdr.get("passphrase")

        if app_key:
            salt = b64url_decode(app_key["salt"])
            wrap = b64url_decode(app_key["wrap"])
            kdks = self._custodian_kdks(salt)
            for kdk in kdks:
                try:
                    dek = ChaCha20Poly1305(kdk).decrypt(wrap[:12], wrap[12:], salt)
                    if dek:
                        break
                except Exception:
                    continue

        if dek is None and passphrase_wrap:
            if not password:
                hint = f"\nپیام سازنده: {creator_message}" if creator_message else ""
                raise ValueError(f"این فایل دارای رمز عبور است. لطفاً رمز عبور را وارد کنید.{hint}")
            salt = b64url_decode(passphrase_wrap["salt"])
            wrap = b64url_decode(passphrase_wrap["wrap"])
            iters = passphrase_wrap.get("iters", 600000)
            derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, 32)
            try:
                dek = ChaCha20Poly1305(derived).decrypt(wrap[:12], wrap[12:], salt)
            except Exception:
                raise ValueError("رمز عبور وارد شده نادرست است.")

        if dek is None:
            if passphrase_wrap and not app_key:
                raise ValueError("این فایل با پسورد قفل شده است. رمز عبور الزامی است.")
            raise ValueError("امکان استخراج کلید رمزگشایی (DEK) وجود ندارد.")

        # Decrypt payload body
        try:
            pt = ChaCha20Poly1305(dek).decrypt(nonce, body_ct_tag, hdr_raw)
        except Exception as e:
            raise ValueError(f"خطا در بازگشایی بدنه پیام ChaCha20: {e}")

        pt_text = decode_sentinels(pt.decode("utf-8", errors="replace"))

        # Parse configs
        links = []
        raw_blocks = []
        try:
            obj = json.loads(pt_text)
            obj = walk_decode_sentinels(obj)
            links = self._extract_all_links(obj)
            if not links:
                raw_blocks.append((0, json.dumps(obj, ensure_ascii=False, indent=2)))
        except Exception:
            links = extract_links_from_json(pt_text)
            if not links:
                raw_blocks.append((0, pt_text))

        return {
            "links": links,
            "raw_blocks": raw_blocks,
            "creator_message": creator_message,
            "metadata": {"configId": hdr.get("configId"), "policy": policy},
        }

    def _custodian_kdks(self, salt: bytes) -> List[bytes]:
        material = bytearray(32)
        material[:16] = salt[:16]
        prefix = b"npvtunnel/appkey/v1 "

        kdks = []
        for tlast in self.tlast_variants:
            # Temporarily set table and run CTR
            prev_tlast = self.wb_aes.TBL
            self.wb_aes.TBL = tlast
            try:
                stream = self.wb_aes._ctr(material[:16], bytes(material[16:]))
                kdk = hashlib.sha256(prefix + stream).digest()
                kdks.append(kdk)
            finally:
                self.wb_aes.TBL = prev_tlast
        return kdks

    def _decrypt_gen2(self, data: bytes, password: str = "") -> Dict[str, Any]:
        hdr_len = struct.unpack(">I", data[5:9])[0]
        if 9 + hdr_len > len(data):
            raise ValueError("طول هدر Gen2 نامعتبر است.")

        h = data[9 : 9 + hdr_len]
        if h[0] != 1:
            raise ValueError(f"نسخه فشرده هدر Gen2 پشتیبانی نمی‌شود: {h[0]}")

        config_id = h[1:17]
        method = h[50]
        recipients = struct.unpack(">H", h[51:53])[0]
        off = 53 + recipients * (32 + 0x5D)

        iters = 0
        if method == 2:  # AppKey
            if off + 78 > len(h):
                raise ValueError("بخش AppKey در هدر ناقص است.")
            salt = h[off + 2 : off + 18]
            wrap = h[off + 18 : off + 78]
            off += 78
        elif method == 1:  # Passphrase
            if off + 80 > len(h):
                raise ValueError("بخش Passphrase در هدر ناقص است.")
            iters = struct.unpack(">I", h[off : off + 4])[0]
            salt = h[off + 4 : off + 20]
            wrap = h[off + 20 : off + 80]
            off += 80
        else:
            raise ValueError(f"روش بازگشایی Gen2 با شناسه {method} نیازمند کلید خصوصی گیرنده است.")

        meta_len = struct.unpack(">I", h[off : off + 4])[0]
        meta_blob = h[off + 4 : off + 4 + meta_len]
        prefix = h[:off]

        nonce_off = 9 + hdr_len
        nonce = data[nonce_off : nonce_off + 12]
        body_len = struct.unpack(">I", data[nonce_off + 12 : nonce_off + 16])[0]
        body_off = nonce_off + 16
        body = data[body_off : body_off + body_len]

        # Derive KDK
        if method == 2:
            a16 = self._gen2_a16(salt)
            kdk = hashlib.sha256(b"npvtunnel/appkey/v2 " + a16 + config_id).digest()
        else:
            if not password:
                raise ValueError("این فایل NPVS دارای رمز عبور است. لطفاً رمز عبور را وارد نمایید.")
            kdk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, 32)

        # Unwrap DEK
        try:
            dek = ChaCha20Poly1305(kdk).decrypt(wrap[:12], wrap[12:], salt)
        except Exception:
            if method == 1:
                raise ValueError("رمز عبور فایل NPVS نادرست است.")
            raise ValueError("بازگشایی کلید رمزگذاری AppKey ناموفق بود.")

        # Metadata decrypt
        metadata = {}
        creator_message = ""
        try:
            meta_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=nonce,
                info=b"NPVS-v5/metadata",
            ).derive(dek)
            meta_bytes = ChaCha20Poly1305(meta_key).decrypt(nonce, meta_blob, prefix)
            metadata = json.loads(meta_bytes.decode("utf-8"))
            policy = metadata.get("policy", {}) or {}
            msg_parts = [
                m.strip().replace("\r\n", "\n")
                for m in [policy.get("displayMessage"), policy.get("customServerMessage")]
                if m and m.strip()
            ]
            creator_message = "\n".join(msg_parts)
        except Exception:
            pass

        # Body parsing
        if len(body) < 38 or body[:4] != b"NPF\x01":
            raise ValueError("فرمت بدنه NPF نامعتبر است.")

        content_id = body[4:36]
        count = struct.unpack(">H", body[36:38])[0]
        b_off = 38
        fields = {}

        for _ in range(count):
            if b_off + 6 > len(body):
                break
            seq, flags, blob_len = struct.unpack(">HHH", body[b_off : b_off + 6])
            blob = body[b_off + 6 : b_off + 6 + blob_len]
            b_off += 6 + blob_len

            field_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=content_id,
                info=b"NPV-fields-v1/field/" + struct.pack(">H", seq),
            ).derive(dek)

            pt_len = len(blob) - 16
            if pt_len < 0:
                continue

            aad = (
                b"NPV-fields-v1/record/"
                + content_id
                + struct.pack(">H", seq)
                + struct.pack(">I", pt_len)
            )

            try:
                pt = ChaCha20Poly1305(field_key).decrypt(bytes(12), blob, aad)
                fields[seq] = pt
            except Exception:
                continue

        # Sentinel table (seq 0xFFFF)
        sentinel_table_bytes = fields.get(0xFFFF)
        links = []
        raw_blocks = []

        if sentinel_table_bytes:
            try:
                spec = json.loads(sentinel_table_bytes.decode("utf-8"))
                for cfg in spec.get("configs", []):
                    subbed = self._gen2_substitute(cfg, fields)
                    link = self._config_to_link(subbed)
                    if link:
                        links.append(link)
            except Exception:
                pass

        if not links:
            # Fallback: inspect raw fields
            field_lines = []
            for seq in sorted(fields.keys()):
                if seq == 0xFFFF:
                    continue
                txt = self._gen2_field_text(fields[seq])
                field_lines.append(f"seq={seq}: {txt}")
            if field_lines:
                raw_blocks.append((0, "\n".join(field_lines)))

        return {
            "links": links,
            "raw_blocks": raw_blocks,
            "creator_message": creator_message,
            "metadata": metadata,
        }

    def _gen2_a16(self, salt: bytes) -> bytes:
        tables = self._get_gen2_tables()
        state = list(salt)

        for b in range(13):
            block = tables[b * 57344 : (b + 1) * 57344]
            state = [state[SHIFT_ORDER[i]] for i in range(16)]
            for j in range(4):
                self._gen2_group(state, block, j)

        page = tables[13 * 57344 :]
        return bytes([page[0x100 * i + state[SHIFT_ORDER[i]]] for i in range(16)])

    @staticmethod
    def _gen2_be32(b: bytes, off: int) -> int:
        return (b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]

    def _gen2_group(self, state: List[int], block: bytes, j: int) -> None:
        s = state[4 * j : 4 * j + 4]
        base1 = 0x6000 + 0x1000 * j
        args1 = [
            self._gen2_be32(block, base1 + 4 * s[0]),
            self._gen2_be32(block, base1 + 0x400 + 4 * s[1]),
            self._gen2_be32(block, base1 + 0x800 + 4 * s[2]),
            self._gen2_be32(block, base1 + 0xC00 + 4 * s[3]),
        ]
        w1 = self._gen2_sub7dc0(block, j, *args1)
        state[4 * j : 4 * j + 4] = w1

        base2 = 0xA000 + 0x1000 * j
        args2 = [
            self._gen2_be32(block, base2 + 4 * w1[0]),
            self._gen2_be32(block, base2 + 0x400 + 4 * w1[1]),
            self._gen2_be32(block, base2 + 0x800 + 4 * w1[2]),
            self._gen2_be32(block, base2 + 0xC00 + 4 * w1[3]),
        ]
        w2 = self._gen2_sub7dc0(block, j, *args2)
        state[4 * j : 4 * j + 4] = w2

    @staticmethod
    def _gen2_sub7dc0(block: bytes, i: int, x3: int, x4: int, x5: int, x6: int) -> List[int]:
        m32 = lambda v: v & 0xFFFFFFFF
        at = lambda addr: block[addr]

        x2 = i
        x3, x4, x5, x6 = m32(x3), m32(x4), m32(x5), m32(x6)

        x8 = m32(x2 + m32(x2 << 1))
        x12 = m32(x3 >> 0x14)
        x11 = m32(x3 >> 0x18)
        x13 = (x4 >> 0x18) & 0xF
        x14 = m32(x5 >> 0x18)
        x10 = x6
        x9 = m32(x8 << 3)
        x8 = x4
        x12 &= 0xF0
        x12 += x13
        x13 = m32(x5 >> 0x14)
        x16 = x8 >> 0x1C
        x9 &= 0xFFFFFFFF
        x11 &= 0xF0
        x14 &= 0xF0
        x15 = m32(x6 >> 0x18) & 0xF
        x13 &= 0xF0
        x17 = m32(x3 >> 0x10)
        x9 <<= 8
        x8 &= 0xF
        x13 += x15
        x17 &= 0xF0
        x11 = x9 + x11
        x14 = x9 + x14
        x12 = x9 + x12
        x16 = at(x11 + x16)
        x14 += x10 >> 28
        x12 = at(x12 + 0x200)
        x13 = x9 + x13
        x0 = m32(x6 >> 0x14) & 0xF
        x14 = at(x14 + 0x100)
        x15 = x9 + (x16 << 4)
        x13 = at(x13 + 0x300)
        x12 = x9 + (x12 << 4)
        x16 = m32(x4 >> 0x14) & 0xF
        x10 &= 0xF
        x14 = x15 + x14
        x15 = m32(x5 >> 0x10)
        x12 += x13
        x13 = m32(x3 >> 0xC)
        x14 = at(x14 + 0x400)
        x12 = at(x12 + 0x500)
        x15 &= 0xF0
        x16 = x17 + x16
        x15 += x0
        x0 = m32(x4 >> 0x10) & 0xF
        x17 = m32(x5 >> 0xC)
        x12 |= x14 << 4
        x13 &= 0xF0
        x14 = m32(x6 >> 0x10) & 0xF
        x13 += x0
        x17 &= 0xF0
        x16 = x9 + x16
        out0 = x12 & 0xFF
        x13 = x9 + x13
        x12 = x17 + x14
        x14 = at(x16 + 0x600)
        x13 = at(x13 + 0x800)
        x15 = x9 + x15
        x12 = x9 + x12
        x15 = at(x15 + 0x700)
        x16 = m32(x5 >> 8)
        x12 = at(x12 + 0x900)
        x14 = x9 + (x14 << 4)
        x13 = x9 + (x13 << 4)
        x0 = m32(x6 >> 0xC) & 0xF
        x17 = m32(x3 >> 8)
        x14 += x15
        x12 = x13 + x12
        x13 = x16 & 0xF0
        x14 = at(x14 + 0xA00)
        x12 = at(x12 + 0xB00)
        x15 = m32(x3 >> 4)
        x13 += x0
        x0 = m32(x4 >> 8) & 0xF
        x16 = m32(x4 >> 0xC) & 0xF
        x12 |= x14 << 4
        x14 = x15 & 0xF0
        x17 &= 0xF0
        x14 += x0
        x15 = x9 + 0xC00
        x0 = m32(x5 >> 4)
        x17 = x15 + x17
        out1 = x12 & 0xFF
        x12 = m32(x6 >> 8) & 0xF
        x16 = at(x17 + x16)
        x14 = x9 + x14
        x17 = x0 & 0xF0
        x14 = at(x14 + 0xE00)
        x12 = x17 + x12
        x13 = x15 + x13
        x12 = x9 + x12
        x13 = at(x13 + 0x100)
        x15 = x9 + (x16 << 4)
        x12 = at(x12 + 0xF00)
        x14 = x9 + (x14 << 4)
        x16 = 0x1000
        x13 = x15 + x13
        x17 = m32(x6 >> 4) & 0xF
        x0 = x5 & 0xF0
        x12 = x14 + x12
        x14 = 0x1100
        x13 = at(x13 + x16)
        x12 = at(x12 + x14)
        x14 = 0x1200
        x15 = m32(x4 >> 4) & 0xF
        x16 = x3 & 0xF0
        x17 = x0 + x17
        x14 = x9 + x14
        x12 |= x13 << 4
        x13 = (x3 & 0xF) << 4
        x16 = x14 + x16
        out2 = x12 & 0xFF
        x8 = x13 + x8
        x12 = x14 + x17
        x14 = (x5 & 0xF) << 4
        x13 = at(x16 + x15)
        x8 = x9 + x8
        x15 = 0x1400
        x12 = at(x12 + 0x100)
        x8 = at(x8 + x15)
        x10 = x14 + x10
        x14 = 0x1500
        x10 = x9 + x10
        x13 = x9 + (x13 << 4)
        x10 = at(x10 + x14)
        x8 = x9 + (x8 << 4)
        x9 = x13 + x12
        x12 = 0x1600
        x8 += x10
        x10 = 0x1700
        x9 = at(x9 + x12)
        x8 = at(x8 + x10)
        x8 |= x9 << 4
        out3 = x8 & 0xFF
        return [out0, out1, out2, out3]

    def _gen2_substitute(self, v: Any, fields: Dict[int, bytes]) -> Any:
        if isinstance(v, (int, float)):
            seq = int(v)
            raw = fields.get(seq, b"")
            txt = self._gen2_field_text(raw)
            return decode_sentinels(txt)
        elif isinstance(v, dict):
            return {k: self._gen2_substitute(val, fields) for k, val in v.items()}
        elif isinstance(v, list):
            return [self._gen2_substitute(val, fields) for val in v]
        return v

    @staticmethod
    def _gen2_field_text(raw: bytes) -> str:
        s = raw.decode("utf-8", errors="replace").strip()
        if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
            try:
                return json.loads(s)
            except Exception:
                return s[1:-1]
        return s

    def _config_to_link(self, cfg: Any) -> Optional[str]:
        if not isinstance(cfg, dict):
            return str(cfg)

        remarks = str(cfg.get("name") or cfg.get("remarks") or "NPVS-Extracted")
        address = str(cfg.get("address") or "")

        if "v2rayProfile" in cfg and isinstance(cfg["v2rayProfile"], dict):
            return self._v2ray_profile_to_link(remarks, address, cfg["v2rayProfile"])
        if "sshConfig" in cfg and isinstance(cfg["sshConfig"], dict):
            return self._ssh_config_to_link(remarks, cfg["sshConfig"])

        for kind in ("socksConfig", "socksProfile", "httpConfig", "httpProfile", "proxyConfig"):
            if kind in cfg and isinstance(cfg[kind], dict):
                return self._proxy_config_to_link(remarks, address, kind, cfg[kind])

        # Try standard item_to_links from link_builder
        links = item_to_links(cfg)
        return links[0] if links else None

    def _v2ray_profile_to_link(self, remarks: str, address: str, p: Dict[str, Any]) -> Optional[str]:
        # Convert all values to string
        str_p = {k: str(v) if v is not None else "" for k, v in p.items()}
        host = str_p.get("server") or address
        port = int(str_p.get("serverPort") or str_p.get("port") or 0)
        config_type = int(str_p.get("configType") or 0)
        profile_remarks = str_p.get("remarks") or remarks

        if config_type == 1:  # VMess
            return self._vmess_link(host, port, profile_remarks, str_p)
        elif config_type == 5:  # VLESS
            return self._vless_link(host, port, profile_remarks, str_p)
        elif config_type == 6:  # Trojan
            return self._trojan_link(host, port, profile_remarks, str_p)
        elif config_type == 3:  # Shadowsocks
            return self._shadowsocks_link(host, port, profile_remarks, str_p)

        # Fallback to general item_to_links
        links = item_to_links(p)
        return links[0] if links else None

    @staticmethod
    def _vless_link(host: str, port: int, remarks: str, p: Dict[str, str]) -> str:
        network = p.get("network", "tcp") or "tcp"
        security = p.get("security", "none") or "none"
        q = {"type": network, "security": security}

        if network == "ws":
            if p.get("path"):
                q["path"] = p["path"]
            if p.get("host"):
                q["host"] = p["host"]
        elif network == "grpc":
            if p.get("serviceName"):
                q["serviceName"] = p["serviceName"]
            q["mode"] = p.get("mode") or p.get("xhttpMode") or "gun"
            if p.get("authority"):
                q["authority"] = p["authority"]
        elif network == "kcp":
            if p.get("headerType"):
                q["headerType"] = p["headerType"]
            if p.get("seed"):
                q["seed"] = p["seed"]
        elif network in ("xhttp", "httpupgrade"):
            if p.get("path"):
                q["path"] = p["path"]
            if p.get("host"):
                q["host"] = p["host"]
            mode = p.get("xhttpMode") or p.get("mode")
            if mode:
                q["mode"] = mode
            if p.get("xhttpExtra"):
                q["extra"] = p["xhttpExtra"]
        elif network in ("tcp", "raw"):
            if p.get("headerType") and p.get("headerType") != "none":
                q["headerType"] = p["headerType"]
                if p.get("host"):
                    q["host"] = p["host"]
                if p.get("path"):
                    q["path"] = p["path"]

        if security == "tls":
            if p.get("sni"):
                q["sni"] = p["sni"]
            if p.get("fingerPrint"):
                q["fp"] = p["fingerPrint"]
            if p.get("alpn"):
                q["alpn"] = p["alpn"]
            if p.get("tlsAllowInsecure", "").lower() in ("true", "1", "yes") or p.get(
                "insecure", ""
            ).lower() in ("true", "1", "yes"):
                q["allowInsecure"] = "1"
        elif security == "reality":
            if p.get("sni"):
                q["sni"] = p["sni"]
            if p.get("fingerPrint"):
                q["fp"] = p["fingerPrint"]
            if p.get("publicKey"):
                q["pbk"] = p["publicKey"]
            if p.get("shortId"):
                q["sid"] = p["shortId"]
            if p.get("spiderX"):
                q["spx"] = p["spiderX"]

        q["encryption"] = p.get("method") if p.get("method", "").strip() else "none"
        if p.get("flow"):
            q["flow"] = p["flow"]

        qs = urllib.parse.urlencode(sorted(q.items()))
        rem = urllib.parse.quote(remarks)
        pwd = p.get("password", "")
        return f"vless://{pwd}@{host}:{port}?{qs}#{rem}"

    @staticmethod
    def _trojan_link(host: str, port: int, remarks: str, p: Dict[str, str]) -> str:
        network = p.get("network", "tcp") or "tcp"
        security = p.get("security", "none") or "none"
        q = {"type": network, "security": security}

        if network == "ws":
            if p.get("path"):
                q["path"] = p["path"]
            if p.get("host"):
                q["host"] = p["host"]
        elif network == "grpc":
            if p.get("serviceName"):
                q["serviceName"] = p["serviceName"]
            q["mode"] = p.get("mode") or "gun"
            if p.get("authority"):
                q["authority"] = p["authority"]

        if security == "tls":
            if p.get("sni"):
                q["sni"] = p["sni"]
            if p.get("fingerPrint"):
                q["fp"] = p["fingerPrint"]
            if p.get("alpn"):
                q["alpn"] = p["alpn"]
            if p.get("tlsAllowInsecure", "").lower() in ("true", "1", "yes") or p.get(
                "insecure", ""
            ).lower() in ("true", "1", "yes"):
                q["allowInsecure"] = "1"

        if p.get("flow"):
            q["flow"] = p["flow"]

        qs = urllib.parse.urlencode(sorted(q.items()))
        rem = urllib.parse.quote(remarks)
        pwd = urllib.parse.quote(p.get("password", ""))
        return f"trojan://{pwd}@{host}:{port}?{qs}#{rem}"

    @staticmethod
    def _vmess_link(host: str, port: int, remarks: str, p: Dict[str, str]) -> str:
        network = p.get("network", "tcp") or "tcp"
        header_type = p.get("headerType") or "none"
        host_header = p.get("host", "")
        path = p.get("path", "")

        if network == "kcp":
            path = p.get("path") or p.get("seed", "")
        elif network == "grpc":
            header_type = p.get("mode", "")
            path = p.get("path") or p.get("serviceName", "")
            host_header = p.get("host") or p.get("authority", "")

        sec = p.get("security", "")
        tls = "tls" if sec in ("tls", "reality") else ""
        insecure = ""
        if sec == "tls":
            insecure = (
                "1"
                if p.get("tlsAllowInsecure", "").lower() in ("true", "1", "yes")
                or p.get("insecure", "").lower() in ("true", "1", "yes")
                else "0"
            )

        obj = {
            "v": "2",
            "ps": remarks,
            "add": host,
            "port": str(port),
            "id": p.get("password", ""),
            "aid": str(int(p.get("alterId", 0) or 0)),
            "scy": p.get("method") or "auto",
            "net": network,
            "type": header_type,
            "host": host_header,
            "path": path,
            "tls": tls,
            "sni": p.get("sni", ""),
            "fp": p.get("fingerPrint", ""),
            "alpn": p.get("alpn", ""),
            "insecure": insecure,
        }
        sorted_obj = {k: obj[k] for k in sorted(obj.keys())}
        b = json.dumps(sorted_obj, separators=(",", ":")).encode("utf-8")
        return "vmess://" + base64.b64encode(b).decode("utf-8")

    @staticmethod
    def _shadowsocks_link(host: str, port: int, remarks: str, p: Dict[str, str]) -> str:
        method = p.get("method", "aes-256-gcm")
        password = p.get("password", "")
        user_info = base64.b64encode(f"{method}:{password}".encode("utf-8")).decode("utf-8")
        rem = urllib.parse.quote(remarks)
        return f"ss://{user_info}@{host}:{port}#{rem}"

    @staticmethod
    def _ssh_config_to_link(remarks: str, s: Dict[str, Any]) -> str:
        target = str(s.get("sshHost", ""))
        port = str(s.get("sshPort", ""))
        if port:
            target += f":{port}"

        q = {"remarks": remarks}
        if s.get("sshConfigType"):
            q["sshConfigType"] = str(s["sshConfigType"])
        if s.get("httpProxy"):
            q["httpProxy"] = str(s["httpProxy"])

        qs = urllib.parse.urlencode(sorted(q.items()))
        user = urllib.parse.quote(str(s.get("sshUsername", "")))
        pwd = urllib.parse.quote(str(s.get("sshPassword", "")))
        payload = str(s.get("payload", ""))
        return f"ssh://{user}:{pwd}@{target}?{qs}#{payload}"

    @staticmethod
    def _proxy_config_to_link(remarks: str, address: str, kind: str, p: Dict[str, Any]) -> str:
        scheme = kind.replace("Config", "").replace("Profile", "").lower()
        host = str(p.get("server") or p.get("host") or address)
        port = str(p.get("serverPort") or p.get("port") or p.get("localPort") or "")
        target = f"{host}:{port}" if port else host

        q = {"remarks": remarks}
        for k, v in sorted(p.items()):
            if k not in ("remarks", "server", "host", "port", "serverPort", "localPort") and v:
                q[k] = str(v)

        qs = urllib.parse.urlencode(q)
        user = p.get("username", "")
        pwd = p.get("password", "")
        auth = ""
        if user and pwd:
            auth = f"{urllib.parse.quote(str(user))}:{urllib.parse.quote(str(pwd))}@"
        elif pwd:
            auth = f"{urllib.parse.quote(str(pwd))}@"
        return f"{scheme}://{auth}{target}?{qs}"

    def _extract_all_links(self, obj: Any) -> List[str]:
        configs = []
        if isinstance(obj, dict):
            if "configs" in obj and isinstance(obj["configs"], list):
                configs = obj["configs"]
            else:
                configs = [obj]
        elif isinstance(obj, list):
            configs = obj

        links = []
        for item in configs:
            if isinstance(item, dict):
                link = self._config_to_link(item)
                if link:
                    links.append(link)
                else:
                    sub_links = extract_links_from_json(item)
                    links.extend(sub_links)
        return links
