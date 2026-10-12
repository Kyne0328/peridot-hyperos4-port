"""Bounded ZIP64 compressed-member copy for authenticated generated ROM inputs."""
import hashlib,struct,zipfile

def copy_member(source_path,source,target,entry):
    if entry.flag_bits&9:raise ValueError('encrypted/data-descriptor members unsupported for compressed copy')
    if entry.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):raise ValueError('unsupported compression')
    with source_path.open('rb') as src:
        src.seek(entry.header_offset);header=src.read(30)
        if len(header)!=30:raise ValueError('truncated local header')
        fields=struct.unpack('<4s5H3I2H',header)
        if fields[0]!=b'PK\x03\x04' or fields[2]!=entry.flag_bits or fields[3]!=entry.compress_type or fields[6]!=entry.CRC:raise ValueError('local/central header mismatch')
        name=src.read(fields[9]);encoding='utf-8' if entry.flag_bits&0x800 else 'cp437'
        if name.decode(encoding)!=entry.filename:raise ValueError('local name mismatch')
        start=entry.header_offset+30+fields[9]+fields[10]
        if start>source.start_dir or entry.compress_size>source.start_dir-start:raise ValueError('compressed member outside payload region')
        src.seek(start)
        info=zipfile.ZipInfo(entry.filename,entry.date_time)
        info.compress_type=entry.compress_type;info.flag_bits=entry.flag_bits
        info.create_system=entry.create_system;info.external_attr=entry.external_attr
        info.CRC=entry.CRC;info.file_size=entry.file_size;info.compress_size=entry.compress_size
        info.header_offset=target.fp.tell()
        target._writecheck(info);target._didModify=True
        target.fp.write(info.FileHeader(zip64=True))
        h=hashlib.sha256();left=entry.compress_size
        while left:
            block=src.read(min(left,1024*1024))
            if not block:raise ValueError('short compressed read')
            if target.fp.write(block)!=len(block):raise ValueError('short compressed write')
            h.update(block);left-=len(block)
        target.filelist.append(info);target.NameToInfo[info.filename]=info
        target.start_dir=target.fp.tell()
        return {'compressed_bytes':entry.compress_size,'compressed_sha256':h.hexdigest()}
