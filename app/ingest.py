"""
Make real-world uploads readable before they reach the sandbox.

Files from Kaggle, Excel exports and old CRMs come in every encoding and dialect: Windows-1252
or Latin-1 instead of UTF-8, UTF-16 "Unicode text" from Excel, a byte-order mark, semicolons or
tabs instead of commas, JSON wrapped in an object or written one record per line. The agents
load files with plain pandas defaults, so every upload is normalised once, here, into the form
those defaults read: UTF-8, comma-separated CSV, JSON as an array of records.

Only the Python standard library touches the bytes (codecs, csv, json): no spreadsheet or
dataframe parser runs on the app server. The real parsing still happens inside the sandbox.
"""

import csv
import io
import json

TEXT_EXT = (".csv", ".tsv", ".txt")


class Unreadable(ValueError):
    """The upload can't be turned into a table; the message is shown to the user."""


def _decode(data: bytes) -> tuple[str, str]:
    """(text, encoding name in plain words). Never fails: Latin-1 maps every byte."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16"), "UTF-16"
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace"), "UTF-8 with a byte-order mark (removed)"
    # UTF-16 without a BOM: every other byte is zero in mostly-ASCII text
    head = data[:4000]
    if len(head) > 20 and head[1::2].count(0) > len(head) // 3:
        try:
            return data.decode("utf-16-le"), "UTF-16"
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8"), "UTF-8"
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp1252"), "Windows-1252"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "Latin-1"


def _columns(text: str, delim: str, rows: int = 200) -> list[int]:
    try:
        reader = csv.reader(io.StringIO(text), delimiter=delim)
        out = []
        for i, r in enumerate(reader):
            if i >= rows:
                break
            if r:
                out.append(len(r))
        return out
    except csv.Error:
        return []


def _delimiter(text: str) -> str:
    """The delimiter that splits the most rows into the same number of columns (comma wins ties)."""
    sample = text[:200_000]
    best, best_score = ",", -1.0
    for d in (",", ";", "\t", "|"):
        counts = _columns(sample, d)
        if not counts:
            continue
        width = max(set(counts), key=counts.count)
        if width < 2:
            continue
        score = counts.count(width) / len(counts) + width / 1000      # consistency first, then width
        if score > best_score + 0.02:
            best, best_score = d, score
    return best


_NAMES = {",": "commas", ";": "semicolons", "\t": "tabs", "|": "pipes"}


def _json_records(text: str):
    """A list of records from: an array, an object holding one big array, or JSON Lines."""
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        recs = []
        for i, ln in enumerate(text.splitlines()):
            if ln.strip():
                try:
                    recs.append(json.loads(ln))
                except json.JSONDecodeError as e:
                    raise Unreadable(f"Line {i + 1} is not valid JSON: {e.msg}.") from None
        return recs, "JSON Lines"
    if isinstance(obj, list):
        return obj, None
    if isinstance(obj, dict):
        lists = [(k, v) for k, v in obj.items() if isinstance(v, list) and v and isinstance(v[0], dict)]
        if lists:
            k, v = max(lists, key=lambda kv: len(kv[1]))
            return v, f'the "{k}" list inside the JSON object'
        if all(isinstance(v, dict) for v in obj.values()) and obj:
            return [{"id": k, **v} for k, v in obj.items()], "an object keyed by id"
        return [obj], "a single JSON object"
    raise Unreadable("The JSON file holds a single value, not a table.")


def normalize(filename: str, data: bytes) -> tuple[str, bytes, list[str]]:
    """(filename, bytes the sandbox will read, notes on what was changed, in plain words)."""
    low = filename.lower()
    notes: list[str] = []
    if low.endswith(".xls"):
        if data[:4] == b"PK\x03\x04":                     # really an .xlsx with the wrong name
            return filename[:-4] + ".xlsx", data, ["The file was an .xlsx workbook named .xls; renamed."]
        if data.lstrip()[:1] in (b"<",) or b"\t" in data[:2000]:     # HTML or TSV saved as .xls
            filename, low = filename[:-4] + ".csv", ".csv"
            notes.append("The .xls file was really text; read as a table.")
        else:
            raise Unreadable("Old Excel 97-2003 (.xls) workbooks aren't supported. "
                             "Open it in Excel or Google Sheets and save it as .xlsx or .csv.")
    if low.endswith(".xlsx"):
        if data[:4] != b"PK\x03\x04":
            raise Unreadable("This .xlsx file isn't a valid Excel workbook. Save it again from Excel as .xlsx or .csv.")
        return filename, data, notes
    if not data.strip():
        raise Unreadable("The file is empty.")

    text, enc = _decode(data)
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    if enc != "UTF-8":
        notes.append("Removed the byte-order mark at the start." if enc.startswith("UTF-8") else f"Converted from {enc} to UTF-8.")

    if low.endswith(".json"):
        recs, how = _json_records(text)
        if not recs:
            raise Unreadable("The JSON file has no records.")
        if how:
            notes.append(f"Read {len(recs):,} records from {how}.")
        if how or enc != "UTF-8":
            return filename, json.dumps(recs, ensure_ascii=False).encode(), notes
        return filename, data, notes

    if low.endswith(TEXT_EXT):
        delim = _delimiter(text)
        if delim != ",":
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\n")
            for row in csv.reader(io.StringIO(text), delimiter=delim):
                w.writerow(row)
            text = buf.getvalue()
            notes.append(f"Columns were separated by {_NAMES[delim]}; converted to commas.")
        if not low.endswith(".csv"):
            filename = filename.rsplit(".", 1)[0] + ".csv"
            notes.append(f"Saved as {filename} so every tool reads it the same way.")
        if notes:
            return filename, text.encode("utf-8"), notes
    return filename, data, notes
