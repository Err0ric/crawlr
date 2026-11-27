"""Small real PDF and Office files for the document metadata tests, built in memory. Every
name, company and title in them is invented."""

import io
import zipfile
import zlib

CORE_NS = ('xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
           'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
           'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')


def core_xml(title="Spring price list", author="Odalys Brandtmoor", modified_by="Teodor Vashenko",
             created="2024-03-04T09:15:00Z", modified="2025-11-20T16:42:10Z") -> bytes:
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<cp:coreProperties {CORE_NS}>'
            f'<dc:title>{title}</dc:title><dc:creator>{author}</dc:creator><cp:lastModifiedBy>{modified_by}</cp:lastModifiedBy>'
            f'<cp:revision>4</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified></cp:coreProperties>').encode("utf-8")


def app_xml(application="Microsoft Office Word", version="16.0000", company="Larkspur Tide Supply Ltd") -> bytes:
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            f'<Template>Normal.dotm</Template><Pages>2</Pages><Application>{application}</Application>'
            f'<Company>{company}</Company><AppVersion>{version}</AppVersion></Properties>').encode("utf-8")


BODY = {
    "docx": ("word/document.xml", b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p/></w:body></w:document>'),
    "xlsx": ("xl/workbook.xml", b'<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>'),
    "pptx": ("ppt/presentation.xml", b'<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>'),
}


def office(kind="docx", core: bytes | None = b"", app: bytes | None = b"", extra: dict | None = None) -> bytes:
    """A docx, xlsx or pptx. core/app: b"" for the default member, None to leave it out."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        name, body = BODY[kind]
        zf.writestr(name, body)
        if core is not None:
            zf.writestr("docProps/core.xml", core or core_xml())
        if app is not None:
            zf.writestr("docProps/app.xml", app or app_xml())
        for member, data in (extra or {}).items():
            zf.writestr(member, data)
    return buf.getvalue()


def xmp_packet(title="Annual report 2021", creators=("Odalys Brandtmoor",), tool="Quillwriter 7.2", producer="Tidewater PDF Library 3.1",
               created="2021-02-27T10:00:00+01:00", modified="2021-03-01T08:30:00Z", pdf_schema=True) -> bytes:
    items = "".join(f"<rdf:li>{c}</rdf:li>" for c in creators)
    pdf_ns = ' xmlns:pdf="http://ns.adobe.com/pdf/1.3/"' if pdf_schema else ""
    pdf_el = f"<pdf:Producer>{producer}</pdf:Producer>" if pdf_schema else ""
    return (f'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n<x:xmpmeta xmlns:x="adobe:ns:meta/">'
            f'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            f'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/"{pdf_ns}'
            f' xmp:CreatorTool="{tool}">'
            f'<dc:title><rdf:Alt><rdf:li xml:lang="de">Jahresbericht</rdf:li><rdf:li xml:lang="x-default">{title}</rdf:li></rdf:Alt></dc:title>'
            f'<dc:creator><rdf:Seq>{items}</rdf:Seq></dc:creator>{pdf_el}'
            f'<xmp:CreateDate>{created}</xmp:CreateDate><xmp:ModifyDate>{modified}</xmp:ModifyDate>'
            f'</rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end="w"?>').encode("utf-8")


INFO = (b"<< /Title (Annual report \\(2021\\)) /Author (Odalys Brandtmoor) /Creator (Quillwriter 7.2) "
        b"/Producer (Tidewater PDF Library 3.1) /CreationDate (D:20210227100000+01'00') /ModDate (D:20210301083000Z) "
        b"/Company (Larkspur Tide Supply Ltd) /Trapped /False >>")


def pdf(info: bytes | None = INFO, *, xmp: bytes | None = None, catalog_metadata: bool = True, extra_objects: tuple = (),
        trailer_extra: bytes = b"", info_in_file: bool = True) -> bytes:
    """A one-page PDF with a cross-reference table. Objects: 1 catalog, 2 pages, 3 page,
    4 info (when given), 5 XMP metadata (when given), then `extra_objects` (bytes each).
    info_in_file=False keeps the trailer's /Info reference and leaves the object out."""
    objects: dict[int, bytes] = {}
    meta = b" /Metadata 5 0 R" if xmp is not None and catalog_metadata else b""
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R" + meta + b" >>"
    objects[2] = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
    objects[3] = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"
    if info is not None and info_in_file:
        objects[4] = info
    if xmp is not None:
        objects[5] = b"<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n" % len(xmp) + xmp + b"\nendstream"
    for n, body in enumerate(extra_objects, start=6):
        objects[n] = body
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    size = max(objects) + 1
    start = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for num in range(1, size):
        out += b"%010d 00000 n \n" % offsets[num] if num in offsets else b"0000000000 65535 f \n"
    out += b"trailer\n<< /Size %d /Root 1 0 R" % size
    if info is not None:
        out += b" /Info 4 0 R"
    out += trailer_extra + b" >>\nstartxref\n%d\n%%%%EOF\n" % start
    return bytes(out)


def object_stream(body: bytes = INFO, *, parms: bytes = b"", filter_name: bytes = b"/FlateDecode", number: int = 4) -> bytes:
    """An object stream as PDF 1.5 writes it: other objects, deflated. `parms` adds a
    /DecodeParms entry (a predictor), which the reader does not unpack."""
    head = b"%d 0 " % number
    data = zlib.compress(head + body)
    return (b"<< /Type /ObjStm /N 1 /First %d /Filter %s%s /Length %d >>\nstream\n" % (len(head), filter_name, parms, len(data))
            + data + b"\nendstream")


PREDICTOR = b" /DecodeParms << /Predictor 12 /Columns 4 >>"
