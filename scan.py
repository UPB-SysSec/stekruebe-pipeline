import json
import uuid
import sys
import subprocess
import base64
import secrets
import struct


class ClientHello:
    """
    Class for building a raw ClientHello message from scratch

    Defined as:
    struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;

    struct {
        uint8 major;
        uint8 minor;
    } ProtocolVersion;

    ProtocolVersion version = { 3, 3 };     /* TLS v1.2*/

    struct {
        uint32 gmt_unix_time;
        opaque random_bytes[28];
    } Random;

    opaque SessionID<0..32>;

    uint8 CipherSuite[2];

    enum { null(0), (255) } CompressionMethod;

    enum {
        signature_algorithms(13), (65535)
    } ExtensionType;

    struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } Extension;

    Bytes are encoded big-endian in order of appearance in struct.

    Variable length vectors v<lower...upper> can range from lower to upper many bytes.
    They are prefixed with length fields specifying the number of consumed bytes, always using as many bytes as necessary to display the maximum.

    For fixed length vectors the length is not included.

    An enumerated occupies as much space in the byte stream as would its maximal defined ordinal value.
    """

    def __init__(self):
        self._client_version = bytes(
            (0x03, 0x03)
        )  # We only can/want TLS1.2 with Zgrab2
        self._random_bytes = secrets.token_bytes(32)
        self._session_id = secrets.token_bytes(0)
        self._cipher_suites = (
            self._get_openssl_default_cipher_suites()
        )  # list of bytes, each two are a cipher suite
        self._compression_methods = [
            0x00,
        ]  # Compression is always null, list of bytes
        self._extensions = []

    def _get_openssl_default_cipher_suites(self):
        """
        List of ciphersuites in their native representation, as used by OpenSSL s_client without further parameters
        """
        return [
            0xC0,
            0x2C,
            0xC0,
            0x30,
            0x00,
            0x9F,
            0xCC,
            0xA9,
            0xCC,
            0xA8,
            0xCC,
            0xAA,
            0xC0,
            0x2B,
            0xC0,
            0x2F,
            0x00,
            0x9E,
            0xC0,
            0x24,
            0xC0,
            0x28,
            0x00,
            0x6B,
            0xC0,
            0x23,
            0xC0,
            0x27,
            0x00,
            0x67,
            0xC0,
            0x0A,
            0xC0,
            0x14,
            0x00,
            0x39,
            0xC0,
            0x09,
            0xC0,
            0x13,
            0x00,
            0x33,
            0x00,
            0x9D,
            0x00,
            0x9C,
            0x00,
            0x3D,
            0x00,
            0x3C,
            0x00,
            0x35,
            0x00,
            0x2F,
            0x00,
            0xFF,
        ]

    def _get_zgrab_default_cipher_suites(self):
        """
        List of ciphersuites in their native representation, as used by zgrab2 tls without further parameters
        """
        return [
            0xC0,
            0x2F,
            0xC0,
            0x2B,
            0xC0,
            0x11,
            0xC0,
            0x07,
            0xC0,
            0x13,
            0xC0,
            0x09,
            0xC0,
            0x14,
            0xC0,
            0x0A,
            0x00,
            0x05,
            0x00,
            0x2F,
            0x00,
            0x35,
            0xC0,
            0x12,
            0x00,
            0x0A,
        ]

    def _encode_vector(self, vector_bytes, max_byte_length):
        """
        Encodes a variable-length byte vector by prepending the length of said vector, contained in k bytes.
        k is the minimal amount of bytes required to represent max_byte_length
        """
        length_field_length = (max_byte_length.bit_length() + 7) // 8
        length_field = len(vector_bytes).to_bytes(length_field_length, "big")
        return length_field + bytes(vector_bytes)

    def _encode_extension(self, extension_type, extension_data):
        res = extension_type.to_bytes(2, "big")
        res += self._encode_vector(extension_data, 2**16 - 1)
        return res

    def _get_sni_extension(self, server_name, name_type=0):
        server_name = self._encode_vector(server_name, 2**16 - 1)
        server_name_list = name_type.to_bytes(1, "big") + server_name
        extension_data = self._encode_vector(server_name_list, 2**16 - 1)
        return self._encode_extension(0, extension_data)

    def encode(self):
        res = b""
        res += self._client_version
        res += self._random_bytes
        res += self._encode_vector(self._session_id, 32)
        res += self._encode_vector(self._cipher_suites, 2**16 - 2)
        res += self._encode_vector(self._compression_methods, 2**8 - 1)
        # Note: zgrab2 will always send renegotiation_info and SNI, but will not respect cmdline arguments for extensions
        res += self._encode_vector(self._extensions, 2**16 - 1)
        return b"\x01" + self._encode_vector(res, 2**24 - 1)


def _execute_zgrab_scan(targets, arguments: list = []):
    # input file for zgrab
    fname = str(uuid.uuid4())
    with open(fname, "w") as f:
        for t in targets:
            f.write(f"{t}\n")
    r = subprocess.run(
        ["zgrab2", "tls", "--session-ticket", "-f", fname] + arguments,
        capture_output=True,
    )
    return r


def _execute_zgrab_scan_with_client_hello(targets, client_hello, arguments: list = []):
    client_hello_string = base64.b64encode(client_hello.encode()).decode("ascii")
    args = [
        f"--client-hello={client_hello_string}",
    ] + arguments
    return _execute_zgrab_scan(targets, arguments=args)


def execute_ticket_redirection_scan(source, targets, batch_size=10):
    ch = ClientHello()
    # empty SessionTicket ext
    ch._extensions = ch._encode_extension(35, b"")
    batches = [targets[i : i + batch_size] for i in range(0, len(targets), batch_size)]
    results = []
    for batch in batches:
        res = _execute_zgrab_scan_with_client_hello(
            [
                source,
            ],
            ch,
        )
        res_json = json.loads(res.stdout)
        # TODO: What do we want for error handling here? i.e. no ticket
        ticket_bytes = base64.b64decode(
            res_json["data"]["tls"]["result"]["handshake_log"]["session_ticket"][
                "value"
            ]
        )
        ch._extensions = ch._encode_extension(35, ticket_bytes)
        res = _execute_zgrab_scan_with_client_hello(batch, ch)
        results = results + [
            res,
        ]
    return results


"""
ch = ClientHello()
# you cannot interfere with these two. Zgrab will crash if you do it wrong and ignore if you do it right
ch._extensions += ch._get_sni_extension(b"timlst.de") # server_name
ch._extensions += ch._encode_extension(65281, b"\x00") # renegotiation_info
# this is explicitly needed when using --client-hello
ch._extensions += ch._encode_extension(35, b"thisisaticket") # session ticket
print(bytes(ch._extensions).hex())
ch_bytes = ch.encode()
print(base64.b64encode(ch_bytes))
print(ch_bytes.hex())
"""
execute_ticket_redirection_scan(
    "fastly.com", ["google.com", "reddit.com", "youtube.com", "twitter.com"], 4
)
