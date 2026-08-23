"""Round-trip tests for msg_parser.py against synthetic .msg files.

There is no real Outlook available to produce a genuine .msg fixture, and
the TypeScript reference has no unit tests of its own for msgToRawEmail's
binary parsing either (see typescript/test/emailparser.test.ts, which only
ever feeds it already-parsed extraAttachments). These tests build the
compound-file structure by hand with extract_msg's own OleWriter — an
independent code path from the reader this module actually uses — so this
is a real round-trip check, not the reader validating its own encoder.
"""

from __future__ import annotations

import io
import struct

import pytest
from extract_msg.ole_writer import OleWriter

from phish_signals.msg_parser import msg_to_raw_email
from phish_signals.sanitize import ValidationError

_PT_UNICODE = 0x001F
_PT_BINARY = 0x0102
_PT_LONG = 0x0003


def _var_entry(prop_id: int, prop_type: int, byte_length: int) -> bytes:
    # type(2) + id(2) + flags(4, unused here) + length(4) + reserved(4) = 16 bytes.
    return (
        struct.pack("<HH", prop_type, prop_id)
        + struct.pack("<I", 0)
        + struct.pack("<II", byte_length, 0)
    )


def _string_entry(prop_id: int, byte_length: int) -> bytes:
    return _var_entry(prop_id, _PT_UNICODE, byte_length)


def _long_entry(prop_id: int, value: int) -> bytes:
    return (
        struct.pack("<HH", _PT_LONG, prop_id)
        + struct.pack("<I", 0)
        + struct.pack("<iI", value, 0)
    )


def _unicode_stream(value: str) -> bytes:
    # extract_msg's getStringStream() decodes a string substg stream's raw
    # bytes as-is with no trailing-null stripping of its own, so the fixture
    # must not add one either.
    return value.encode("utf-16-le")


def _properties_stream(header_size: int, entries: bytes) -> bytes:
    return b"\x00" * header_size + entries


def _build_msg(
    *,
    subject: str | None = None,
    body: str | None = None,
    header_text: str | None = None,
    sender_name: str | None = None,
    sender_smtp: str | None = None,
    attachment_filename: str | None = None,
    attachment_size: int | None = None,
) -> bytes:
    writer = OleWriter()

    entries = b""
    substg_streams: dict[str, bytes] = {}

    def add_string(prop_id: int, value: str) -> None:
        nonlocal entries
        data = _unicode_stream(value)
        entries += _string_entry(prop_id, len(data))
        substg_streams[f"__substg1.0_{prop_id:04X}{_PT_UNICODE:04X}"] = data

    # PR_MESSAGE_CLASS — extract_msg.openMsg() refuses to recognize anything
    # without this as an MSG file at all, regardless of what else is present.
    add_string(0x001A, "IPM.Note")

    if subject is not None:
        add_string(0x0037, subject)
    if body is not None:
        add_string(0x1000, body)
    if header_text is not None:
        add_string(0x007D, header_text)
    if sender_name is not None:
        add_string(0x0C1A, sender_name)
    if sender_smtp is not None:
        add_string(0x5D01, sender_smtp)

    writer.addEntry(["__properties_version1.0"], _properties_stream(32, entries))
    for name, data in substg_streams.items():
        writer.addEntry([name], data)

    # The named-properties mapping storage — extract_msg requires its three
    # streams to exist (even empty) on every MSG file, whether or not any
    # named property is actually used.
    writer.addEntry(["__nameid_version1.0"], storage=True)
    writer.addEntry(["__nameid_version1.0", "__substg1.0_00020102"], b"")
    writer.addEntry(["__nameid_version1.0", "__substg1.0_00030102"], b"")
    writer.addEntry(["__nameid_version1.0", "__substg1.0_00040102"], b"")

    if attachment_filename is not None:
        writer.addEntry(["__attach_version1.0_#00000000"], storage=True)
        att_entries = _string_entry(0x3707, len(_unicode_stream(attachment_filename)))
        att_entries += _long_entry(0x0E20, attachment_size or 0)
        # PR_ATTACH_METHOD = ATTACH_BY_VALUE — extract_msg requires this to
        # classify the attachment at all.
        att_entries += _long_entry(0x3705, 1)
        # PR_ATTACH_DATA_BIN — extract_msg requires a data-by-value
        # attachment to carry this stream to consider it structurally valid
        # at all, even though msg_to_raw_email() never reads its content.
        placeholder_data = b"placeholder attachment bytes, never read"
        att_entries += _var_entry(0x3701, _PT_BINARY, len(placeholder_data))
        # extract_msg's PropertiesStore skips only 8 header bytes for an
        # ATTACHMENT properties stream (vs. 32 for a top-level MESSAGE one).
        writer.addEntry(
            ["__attach_version1.0_#00000000", "__properties_version1.0"],
            _properties_stream(8, att_entries),
        )
        writer.addEntry(
            ["__attach_version1.0_#00000000", "__substg1.0_3707001F"],
            _unicode_stream(attachment_filename),
        )
        writer.addEntry(
            ["__attach_version1.0_#00000000", "__substg1.0_37010102"],
            placeholder_data,
        )

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def test_preserves_original_transport_headers() -> None:
    raw = _build_msg(
        subject="ignored when headers exist",
        body="Hello there.",
        header_text="From: a@b.com\r\nSubject: Real Subject\r\n",
    )
    result = msg_to_raw_email(raw)
    assert (
        result["rawEmail"]
        == "From: a@b.com\r\nSubject: Real Subject\r\n\r\nHello there."
    )
    assert result["attachments"] == []


def test_synthesizes_headers_from_sender_fields_when_no_transport_headers() -> None:
    raw = _build_msg(
        subject="Hello\r\nWorld",
        body="Body text.",
        sender_name="A Sender",
        sender_smtp="sender@example.com",
    )
    result = msg_to_raw_email(raw)
    assert result["rawEmail"] == (
        'From: "A Sender" <sender@example.com>\r\nSubject: Hello World\r\n\r\n'
        "Body text."
    )


def test_attachment_metadata_is_extracted_without_reading_content() -> None:
    raw = _build_msg(
        body="x",
        sender_smtp="a@b.com",
        attachment_filename="invoice.exe",
        attachment_size=999,
    )
    result = msg_to_raw_email(raw)
    assert result["attachments"] == [
        {
            "filename": "invoice.exe",
            "contentType": "application/octet-stream",
            "size": 999,
        }
    ]


def test_garbage_input_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        msg_to_raw_email(b"not a real msg file" * 200)


def test_too_short_input_raises_validation_error_without_touching_the_filesystem() -> (
    None
):
    with pytest.raises(ValidationError):
        msg_to_raw_email(b"short")
