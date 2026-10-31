"""Offline-built fixed stock/current PIN worker; no USB/session imports."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
from ..research import pin_plan as reference
from . import pin_product as product, pin_sources as sources

SOURCE_SHA256 = "4b53174ae18f17cfb95700492c0a5a96b1f5032c07dba1ac667407bf48d85637"
REQUEST_PATH = "/tmp/jiritsu/m4.pin-family.request"
REPORT_PATH = "/tmp/jiritsu/m4.pin-family.result"
REQUEST = struct.Struct("<8sII16s32s")
_need = product._need
_canonical = product._canonical


def wire_plan(plan, source_images, *, previous_plan=None, previous_source=None, restore_previous=False):
    product.validate_product_pin(plan, source_images)
    _need(type(restore_previous) is bool and (not restore_previous or previous_plan is not None), "Previous-backup restore requires independently validated latest plan")
    runtime = [row["before_hex"] for row in plan["components"]["ap"]["windows"]]
    if previous_plan is not None:
        _need(previous_source is not None, "Previous complete source witnesses required")
        product.validate_product_pin(previous_plan, previous_source)
        _need(previous_plan["source_admission"] == plan["source_admission"],
              "Replacement source admission changed; gate/looks drift is unsupported")
        runtime = [row["after_hex"] for row in previous_plan["components"]["ap"]["windows"]]
    else:
        _need(previous_source is None, "Unexpected previous source witnesses")
    result = {"schema": "a7m4-toolbox-pin-wire-plan/1", "content_plan": deepcopy(plan),
              "previous_forward_plan": deepcopy(previous_plan), "runtime_words": runtime,
              "restore_previous_backup": restore_previous}
    result["plan_id"] = sha256(_canonical(result)).hexdigest()
    return result


def make_request(wire, mode, nonce):
    _need(type(mode) is int and mode in (0, 1, 2, 3), "Fixed mode0..3 required")
    _need(type(nonce) is bytes and len(nonce) == 16 and any(nonce), "Fresh nonzero16B nonce required")
    return REQUEST.pack(b"M4PF0001", mode, 0, nonce, bytes.fromhex(wire["plan_id"]))


def _packets(wire):
    bank = wire["content_plan"]["components"]["bank"]
    values = (b"".join(bytes.fromhex(row["before_hex"]) for row in bank["windows"]),
              b"".join(bytes.fromhex(row["after_hex"]) for row in bank["windows"]) + bytes.fromhex(bank["append_hex"]))
    result = {}
    for index, (name, data) in enumerate(zip(("source", "target"), values)):
        raw = reference.PACK_HEADER.pack(b"M4PIND01", bytes.fromhex(wire["plan_id"]), index, len(data)) + data
        _need(0 < len(raw) < 65536, "Each product packet must be strictly below64KiB")
        filename = "m4.family." + wire["plan_id"][:16] + "." + name + ".bin"
        result[name] = {"file": filename, "upload_path": "/tmp/jiritsu/" + filename,
                        "size": len(raw), "sha256": sha256(raw).hexdigest(), "data": raw}
    return result


def render_header(wire):
    plan, packets = wire["content_plan"], _packets(wire)
    array = lambda raw: "{" + ",".join(str(n) for n in raw) + "}"
    lines = ["/* Source-bound stock/current PIN; no arbitrary path or window. */",
             "struct Window {u64 offset;u32 length,chip;const u8 *before,*after;};"]
    for index, row in enumerate(plan["components"]["ap"]["windows"]):
        for side in ("before", "after"):
            lines.append("static const u8 %s_%d[]=%s;" % (side, index, array(bytes.fromhex(row[side + "_hex"]))))
    lines += ["static const struct Window windows[]={" + ",".join(
        "{%dUL,4,0,before_%d,after_%d}" % (row["offset"], i, i)
        for i, row in enumerate(plan["components"]["ap"]["windows"])) + "};",
        "static const u32 window_count=7;",
        "static const u32 allow_target_runtime=%d;" % int(wire["restore_previous_backup"]),
        "static const u64 file_sizes[]={%dUL,%dUL};" % (plan["components"]["ap"]["source"]["size"], plan["components"]["bank"]["source"]["size"]),
        "static const u8 plan_id[32]=" + array(bytes.fromhex(wire["plan_id"])) + ";",
        "static const u8 previous_plan_id[32]=" + array(bytes.fromhex((wire["previous_forward_plan"] or plan)["plan_id"])) + ";",
        "static const u8 runtime_ap_words[7][4]={" + ",".join(array(bytes.fromhex(h)) for h in wire["runtime_words"]) + "};",
        "static const u8 protected_bank_sha[32]=" + array(bytes.fromhex(plan["protected_bank"]["sha256"])) + ";"]
    for name, row in packets.items():
        lines += ["static const u32 %s_packet_bytes=%d;" % (name, row["size"]),
            "static const u8 %s_packet_sha[32]=%s;" % (name, array(bytes.fromhex(row["sha256"]))),
            'static const char %s_packet_path[]="%s";' % (name, row["upload_path"])]
    return ("\n".join(lines) + "\n").encode()


def _save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def _elf(raw):
    result=reference._validate_elf(raw)
    header=struct.unpack_from("<16sHHIQQQIHHHHHH",raw)
    entries=[];code=[]
    for index in range(header[10]):
        kind,flags,offset,address,_,size,_,_=struct.unpack_from("<IIQQQQQQ",raw,header[5]+index*56)
        _need(kind!=3,"Constructor worker must not contain a program interpreter")
        if kind==1 and flags&1:code.append((address,address+size))
        if kind==2:
            for at in range(offset,offset+size,16):
                tag,value=struct.unpack_from("<qQ",raw,at)
                _need(tag!=22 and not(tag==30 and value&4),"Constructor text relocations rejected")
                if tag==12:entries.append(value)
    _need(len(entries)==1 and entries[0]%4==0 and any(start<=entries[0]<end for start,end in code),
          "Exactly one executable AArch64 DT_INIT constructor required")
    return dict(result,constructor="DT_INIT",text_relocations=False)


def build_product_worker(content_plan, source_images, output, *, compiler=None, previous_plan=None, previous_source=None, restore_previous=False):
    plan = wire_plan(content_plan, source_images, previous_plan=previous_plan, previous_source=previous_source, restore_previous=restore_previous)
    result={"schema":"a7m4-toolbox-pin-worker-bundle/1","plan_id":plan["plan_id"],
        "content_plan_id":plan["content_plan"]["plan_id"],"worker_built":False,
        "status":"BLOCKED_COMPILER_UNAVAILABLE","device_io":False,"network_io":False,
        "device_execution_state":"HELD","blockers":[],
        "request":{"file":REQUEST_PATH,"bytes":64},"report":{"file":REPORT_PATH,"bytes":184}}
    if compiler is None:
        result["blockers"]=["Explicit offline Zig0.13.0 required; no download"]
        return result
    command=[os.fspath(compiler)] if isinstance(compiler,(str,os.PathLike)) else list(compiler)
    _need(command and all(type(x) is str and x for x in command),"Explicit compiler command required")
    canonical=Path(__file__).resolve().parents[2]/"native/pin-family/program.c"
    packaged=Path(__file__).with_name("data")/"pin-family.c"
    sources=[path for path in (packaged,canonical) if path.exists() or path.is_symlink()]
    _need(sources and all(path.is_file() and not path.is_symlink() and sha256(path.read_bytes()).hexdigest()==SOURCE_SHA256
          for path in sources),"Canonical/packaged runtime rebase source binding differs")
    directory=Path(output).absolute()
    _need(not directory.exists() and directory.parent.is_dir() and not any(path.is_symlink() for path in (directory,*directory.parents)),
          "New private product PIN build directory required")
    directory.mkdir(mode=0o700)
    packets=_packets(plan)
    for row in packets.values():_save(directory/row["file"],row["data"])
    result["packets"]={name:{key:value for key,value in row.items() if key!="data"} for name,row in packets.items()}
    result["output_dir"]=str(directory)
    header=render_header(plan);_save(directory/"patch_manifest.h",header)
    _save(directory/"wire-plan.json",_canonical(plan)+b"\n")
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(directory/"zig-global"),ZIG_LOCAL_CACHE_DIR=str(directory/"zig-local"))
    try:
        version=subprocess.run(command+["version"],capture_output=True,text=True,check=True,timeout=20,env=env).stdout.strip()
        _need(version=="0.13.0","Reviewed Zig0.13.0 required")
        common=command+["cc","-target","aarch64-linux-gnu","-std=c11","-O2","-ffreestanding","-fno-builtin","-I",str(directory)]
        abi=directory/"target-abi.o"
        subprocess.run(common+["-DM4_FL23_TARGET_ABI_CHECK","-c",str(sources[0]),"-o",str(abi)],
                       capture_output=True,check=True,timeout=180,env=env);abi.chmod(0o600)
        flags=["-Wall","-Wextra","-Werror","-shared","-fPIC","-fno-stack-protector","-fno-unwind-tables",
               "-fno-asynchronous-unwind-tables","-nostdlib","-g0","-Wl,--strip-debug","-Wl,--no-undefined",
               "-Wl,--build-id=none","-Wl,-Bsymbolic","-Wl,-z,noexecstack"]
        binaries=[]
        for name in ("pin-family.so","pin-family-repeat.so"):
            path=directory/name
            subprocess.run(common+flags+[str(sources[0]),"-o",str(path)],capture_output=True,check=True,timeout=180,env=env)
            path.chmod(0o600);raw=path.read_bytes()
            _need(0<len(raw)<65536,"Product PIN helper exceeds strict upload bound")
            _elf(raw);binaries.append(raw)
        _need(wire_plan(content_plan, source_images, previous_plan=previous_plan, previous_source=previous_source, restore_previous=restore_previous)==plan, "Source witnesses changed during build")
        _need(binaries[0]==binaries[1] and all(sha256(path.read_bytes()).hexdigest()==SOURCE_SHA256 for path in sources),
              "Product PIN build/source reproducibility failed")
        result.update(worker_built=True,status="BUILT_OFFLINE_NOT_DEVICE_VALIDATED",
            worker={"file":"pin-family.so","size":len(binaries[0]),"sha256":sha256(binaries[0]).hexdigest(),
                    "source_sha256":SOURCE_SHA256,"header_sha256":sha256(header).hexdigest(),
                    "target_abi_sha256":sha256(abi.read_bytes()).hexdigest(),"double_build_identical":True,
                    "compiler":"Zig0.13.0","elf":_elf(binaries[0])})
    except (OSError,subprocess.SubprocessError,ValueError) as error:
        result["status"]="BLOCKED_NATIVE_BUILD"
        detail=getattr(error,"stderr","") or str(error)
        if isinstance(detail,bytes):detail=detail.decode(errors="replace")
        result["blockers"]=[str(detail)[-3000:]]
    _save(directory/"bundle.json",_canonical(result)+b"\n")
    return result


class ProductPinProtocol:
    """Full wire ID/nonces, source barriers, PID+FD binding and unknown latch."""
    def __init__(self, plan, source_images, *, inverse=False, previous_plan=None, previous_source=None, restore_previous=False):
        _need(type(inverse) is bool, "Explicit inverse flag required")
        self.wire = wire_plan(plan, source_images, previous_plan=previous_plan, previous_source=previous_source, restore_previous=restore_previous)
        self.plan = deepcopy(plan)
        self.source_images = sources.images(source_images)
        self.modes = [3, 2, 0] if inverse else [0, 1, 3]
        self.step = 0
        self.pending = None
        self.nonces = set()
        self.failed = False
        self.finished = False
        self.file_identities = None
        self.initial_barrier = False

    def unknown(self):
        self.failed = True
        self.pending = None

    def request(self, mode, nonce):
        _need(not self.failed and not self.finished and self.pending is None and self.step < 3,
              "Product protocol ended, pending or unknown; no replay")
        _need(mode == self.modes[self.step] and nonce not in self.nonces, "Product phase order/nonce replay rejected")
        _need(self.step != 1 or self.initial_barrier, "Complete initial Mac readback required before mutation")
        raw = make_request(self.wire, mode, nonce)
        self.nonces.add(nonce); self.pending = (mode, nonce)
        return raw

    def accept_report(self, raw):
        _need(not self.failed and self.pending is not None, "No pending exact product report")
        try:
            _need(type(raw) is bytes and len(raw) == 184, "Missing/partial native result; STOP_UNKNOWN")
            fields = struct.unpack("<8sIIII7q6Q32s16sq", raw)
            mode, nonce = self.pending
            _need(fields[:2] == (b"M4PFR001", 1) and fields[2:4] == (mode, 9), "Foreign/incomplete product report")
            _need(all(fields[i] == 0 for i in (5, 6, 7, 8, 9, 10, 20)) and fields[11] > 0,
                  "Native operation/cleanup/root identity failed")
            _need(fields[4] == (8 if mode in (1, 2) else 0), "Wrong native persistent write count")
            _need(fields[13] > 0 and fields[16] > 0 and fields[14] == self.plan["components"]["ap"]["source"]["size"]
                and fields[17] == (110528 if mode in (1, 3) else self.plan["components"]["bank"]["source"]["size"]),
                "Product AP/bank size or inode differs")
            _need(fields[18] == bytes.fromhex(self.wire["plan_id"]) and fields[19] == nonce,
                  "Stale nonce or foreign full wire plan")
            actual = (fields[12], fields[13], fields[15], fields[16], fields[11])
            _need(self.file_identities is None or actual == self.file_identities,
                  "AP/bank FD or native process changed across phases")
        except BaseException:
            self.unknown(); raise
        self.pending = None; self.step += 1; self.file_identities = actual
        return {"mode": mode, "phase": 9, "native_completed": True,
                "full_readback_verified": False, "wire_plan_id": self.wire["plan_id"]}

    def confirm_readback(self, images):
        _need(not self.failed and not self.finished and self.pending is None and self.step in (1, 3),
              "Initial or terminal inspect required before full Mac readback")
        mode = self.modes[self.step - 1]
        try:
            result = product.verify_product_readback(self.plan, images, self.source_images,
                                                     "forward" if mode == 3 else "source")
        except BaseException:
            self.unknown(); raise
        if self.step == 1: self.initial_barrier = True
        else: self.finished = True
        return result
