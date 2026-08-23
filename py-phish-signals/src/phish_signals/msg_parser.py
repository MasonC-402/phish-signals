"""Outlook .msg to raw-email conversion.

Port of ``typescript/src/msgParser.ts``.

We don't do anything with .msg structure ourselves beyond reading a few
plain-text fields back out — everything downstream (auth/URL/content
checks) still runs on the same "raw email text" shape as the .eml/paste
path, so none of that analysis code needs to know .msg exists at all.

Uses ``extract_msg`` (built on ``olefile``) to read the compound-file
structure and MAPI properties, matching this module's own pre-existing
guidance that a mature library is the right call here rather than a
hand-rolled binary-format parser — see ``pyproject.toml`` for why this and
``qr_check.py`` are this otherwise-stdlib-only package's two deliberate
dependency exceptions.
"""

from __future__ import annotations

import re

import extract_msg
from extract_msg.attachments.attachment_base import AttachmentBase

from .sanitize import ValidationError
from .types import MsgAttachment, MsgParseResult

_UNREADABLE = (
    "Could not read this .msg file. It may be corrupted or not a valid Outlook message."
)

# olefile treats a short bytes value as a *filename* rather than in-memory
# file content (see olefile.MINIMAL_OLEFILE_SIZE) — a real .msg is always
# far larger than this, so anything under the threshold is rejected outright
# rather than risking a byte string being misread as a filesystem path.
_MINIMAL_OLE_SIZE = 1536

_QUOTE_OR_NEWLINE_RE = re.compile(r'["\r\n]')
_NEWLINES_RE = re.compile(r"[\r\n]+")

# .msg stores attachments as raw extension strings, not MIME types — a rough
# guess is enough here since this only feeds the image-count note, not any
# actual content handling.
_IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"})


def _guess_content_type(extension: str | None) -> str:
    ext = (extension or "").lower()
    if ext in _IMAGE_EXTENSIONS:
        return "image/" + ext[1:]
    return "application/octet-stream"


def _attachment_size(attachment: AttachmentBase) -> int:
    # PR_ATTACH_SIZE (0x0E20, PT_LONG) — declared size only, never the bytes
    # themselves. AttachmentBase exposes no dedicated ``size`` property, so
    # this reads the raw MAPI property tag directly.
    value = attachment.getPropertyVal("0E200003")
    return int(value) if isinstance(value, int) else 0


def msg_to_raw_email(buffer: bytes) -> MsgParseResult:
    if len(buffer) < _MINIMAL_OLE_SIZE:
        raise ValidationError(_UNREADABLE)

    try:
        with extract_msg.openMsg(buffer) as opened:
            if not isinstance(opened, extract_msg.Message):
                # A calendar invite, contact card, task, or other non-email
                # .msg class type — none of body/headerText/subject below
                # are meaningful for those, and this module only ever
                # promised to convert an email message.
                raise ValidationError(_UNREADABLE)
            msg = opened

            body = msg.body or ""
            header_text = msg.headerText

            attachments: list[MsgAttachment] = []
            for attachment in msg.attachments:
                if not isinstance(attachment, AttachmentBase):
                    # A SignedAttachment (S/MIME) carries no independent
                    # filename/size metadata the same way; skipped rather
                    # than guessed at.
                    continue
                filename = (
                    attachment.longFilename or attachment.shortFilename or "(unnamed)"
                )
                attachments.append(
                    {
                        "filename": filename,
                        "contentType": _guess_content_type(attachment.extension),
                        "size": _attachment_size(attachment),
                    }
                )

            # If the .msg still carries its original transport headers
            # (common when a received email was saved to disk as .msg),
            # reuse them as-is — they hold the real Authentication-Results/
            # Return-Path/Reply-To that auth_check.py looks for. Otherwise
            # (e.g. a message drafted natively in Outlook and never
            # transmitted) synthesize a minimal header block from the
            # structured sender/subject fields instead.
            if header_text and header_text.strip():
                return {
                    "rawEmail": header_text.strip() + "\r\n\r\n" + body,
                    "attachments": attachments,
                }

            from_email = (
                msg.getStringStream("__substg1.0_5D01")
                or msg.getStringStream("__substg1.0_0C1F")
                or ""
            )
            from_name = _QUOTE_OR_NEWLINE_RE.sub(
                "", msg.getStringStream("__substg1.0_0C1A") or ""
            )
            from_ = f'"{from_name}" <{from_email}>' if from_name else from_email
            subject = _NEWLINES_RE.sub(" ", msg.subject or "")

            return {
                "rawEmail": f"From: {from_}\r\nSubject: {subject}\r\n\r\n{body}",
                "attachments": attachments,
            }
    except ValidationError:
        raise
    except Exception as exc:
        raise ValidationError(_UNREADABLE) from exc


__all__ = ["msg_to_raw_email"]
