#!/usr/bin/env python3
"""Exact Python zipfile layout estimator for deterministic ASCII ZIP_STORED+forced local ZIP64."""
import zipfile
from sparse_super import check

def estimate_stored_zip(members):
    offset = 0
    cd_size = 0
    records = []
    for member in members:
        name = member["zip_path"]
        encoded = member["encoded_size"]
        check(isinstance(name, str) and name.isascii(), "estimator requires ASCII member names")
        check(isinstance(encoded, int) and encoded >= 0, "invalid encoded member size")
        name_bytes = len(name.encode("ascii"))
        check(0 < name_bytes <= 65535, "invalid ZIP member name length")
        local_size = 30 + name_bytes + 20
        extras = (2 if encoded > zipfile.ZIP64_LIMIT else 0) + (1 if offset > zipfile.ZIP64_LIMIT else 0)
        cd_entry_size = 46 + name_bytes + (4 + 8*extras if extras else 0)
        records.append(dict(zip_path=name, header_offset=offset, data_offset=offset+local_size,
                            encoded_size=encoded, central_directory_entry_bytes=cd_entry_size))
        offset += local_size + encoded
        cd_size += cd_entry_size
    zip64 = len(records) > zipfile.ZIP_FILECOUNT_LIMIT or cd_size > zipfile.ZIP64_LIMIT or offset > zipfile.ZIP64_LIMIT
    tail_size = 22 + (76 if zip64 else 0)
    return {"unsigned_zip_bytes": offset+cd_size+tail_size, "central_directory_offset": offset,
            "central_directory_bytes": cd_size, "end_record_bytes": tail_size,
            "zip64_end_records": zip64, "members": records,
            "assumptions": "ZIP_STORED, force_zip64=True per local entry, ASCII names, fixed times/modes, empty per-entry extras/comments except automatic ZIP64, empty archive comment"}
