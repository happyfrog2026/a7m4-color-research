"""Exact previous-plan runtime words for an explicit PIN replacement.

The original research PIN source/policy is unchanged. This separate constructor
can COW the previous target's private AP pages without changing their semantic
bytes while writing a newly planned R066->new target on disk. It cannot perform
inverse, choose arbitrary runtime bytes, change CP code or authorize a device.
"""
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import struct

from ..research import pin_plan as pin

SCHEMA = "a7m4-pin-runtime-rebase-plan/1"
SOURCE_SHA256 = "af286a932b58d0d6b239b48ab9ce83a71ed7b43dc2dd98dd43f24b67d4dc2413"
REQUEST_PATH = "/tmp/jiritsu/m4.pin-rebase.request"
REPORT_PATH = "/tmp/jiritsu/m4.pin-rebase.result"


def _need(value, text):
    if not value:
        raise ValueError(text)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value):
    return sha256(_canonical(value)).hexdigest()


def _forward(plan):
    # The mature validator binds full R066 identities, all seven word offsets,
    # owned data, fixed native lengths, helper contract and protected complement.
    pin.make_pin_request(plan, 0, bytes(range(1,17)))
    _need(plan["direction"] == "forward" and plan["cutoff"]["requested"] is None,
          "Runtime rebase accepts only a no-cutoff R066 original forward plan")
    _need(plan["components"]["cp_program"]["source"] == plan["components"]["cp_program"]["target"],
          "Runtime rebase never changes CP-program")


def _runtime(previous):
    return {"previous_plan_id": previous["plan_id"],
            "previous_target_ap": copy.deepcopy(previous["components"]["ap"]["target"]),
            "words": [{"offset": row["offset"], "word_hex": row["after_hex"]}
                      for row in previous["components"]["ap"]["windows"]]}


def runtime_rebase_plan(previous, content_plan):
    """Both plans must independently pass the frozen R066 PIN validator.

    The caller additionally proves the previous completed job and fresh complete
    target backup. No caller-supplied runtime whitelist is accepted by this API.
    """
    _forward(previous)
    _forward(content_plan)
    result = {"schema": SCHEMA, "previous_forward_plan": copy.deepcopy(previous),
              "content_plan": copy.deepcopy(content_plan), "runtime_rebase": _runtime(previous)}
    result["plan_id"] = _digest(result)
    return result


def validate_runtime_rebase(plan):
    _need(type(plan) is dict and set(plan) == {"schema", "previous_forward_plan", "content_plan", "runtime_rebase", "plan_id"}
          and plan["schema"] == SCHEMA, "Unsupported runtime rebase plan")
    expected = runtime_rebase_plan(plan["previous_forward_plan"], plan["content_plan"])
    _need(expected == plan, "Runtime whitelist/full plan identity differs from independently validated previous target")
    return plan


def make_request(plan, mode, nonce):
    validate_runtime_rebase(plan)
    _need(type(mode) is int and mode in (0,1,3), "Runtime rebase has no inverse mode")
    pin.make_pin_request(plan["content_plan"], mode, nonce)
    return pin.REQUEST.pack(b"M4PRB001", mode, 0, nonce, bytes.fromhex(plan["plan_id"]))


class RebaseProtocol:
    def __init__(self, plan):
        self.plan = copy.deepcopy(validate_runtime_rebase(plan))
        self.inner = pin.PinWorkerProtocol(self.plan["content_plan"])

    @property
    def file_identities(self):
        return self.inner.file_identities

    def unknown(self):
        self.inner.unknown()

    def request(self, mode, nonce):
        raw = make_request(self.plan, mode, nonce)
        self.inner.request(mode, nonce)
        return raw

    def accept_report(self, raw):
        try:
            _need(type(raw) is bytes and len(raw) == 184, "Missing complete runtime rebase report")
            fields = list(struct.unpack("<8sIIII7q6Q32s16sq",raw))
            _need(fields[0] == b"M4PRBR01" and fields[18] == bytes.fromhex(self.plan["plan_id"]),
                  "Foreign runtime rebase report/full plan ID")
            fields[0] = b"M4PINR01"
            fields[18] = bytes.fromhex(self.plan["content_plan"]["plan_id"])
            converted = struct.pack("<8sIIII7q6Q32s16sq",*fields)
            result = self.inner.accept_report(converted)
            result["runtime_rebase_plan_id"] = self.plan["plan_id"]
            return result
        except BaseException:
            self.unknown()
            raise

    def confirm_readback(self, images):
        return self.inner.confirm_readback(images)


def _packets(plan):
    bank = plan["content_plan"]["components"]["bank"]
    values = (b"".join(bytes.fromhex(w["before_hex"]) for w in bank["windows"]),
              b"".join(bytes.fromhex(w["after_hex"]) for w in bank["windows"]) + bytes.fromhex(bank["append_hex"]))
    result = {}
    for index, (name, data) in enumerate(zip(("source","target"),values)):
        raw = pin.PACK_HEADER.pack(b"M4PIND01",bytes.fromhex(plan["plan_id"]),index,len(data)) + data
        _need(0 < len(raw) < 65536, "Rebase packet exceeds upload bound")
        filename = "m4.rebase." + plan["plan_id"][:16] + "." + name + ".bin"
        result[name] = {"file":filename,"upload_path":"/tmp/jiritsu/"+filename,"size":len(raw),
                        "sha256":sha256(raw).hexdigest(),"data":raw}
    return result


def render_header(plan, packets=None):
    validate_runtime_rebase(plan)
    packets = _packets(plan) if packets is None else packets
    content = plan["content_plan"]
    array = lambda raw: "{"+",".join(str(v) for v in raw)+"}"
    lines = ["/* Generated only from separately validated R066 forward plans. */",
             "struct Window {u64 offset;u32 length,chip;const u8 *before,*after;};"]
    for index,row in enumerate(content["components"]["ap"]["windows"]):
        for side in ("before","after"):
            lines.append("static const u8 %s_%d[]=%s;" % (side,index,array(bytes.fromhex(row[side+"_hex"]))))
    lines += ["static const struct Window windows[]={"+",".join(
        "{%dUL,4,0,before_%d,after_%d}" % (row["offset"],index,index)
        for index,row in enumerate(content["components"]["ap"]["windows"]))+"};",
        "static const u32 window_count=7;",
        "static const u64 file_sizes[]={%dUL,%dUL};" % (pin.BASELINE["ap"]["size"],pin.BASELINE["bank"]["size"]),
        "static const u8 plan_id[32]="+array(bytes.fromhex(plan["plan_id"]))+";",
        "static const u8 previous_plan_id[32]="+array(bytes.fromhex(plan["runtime_rebase"]["previous_plan_id"]))+";",
        "static const u8 runtime_ap_words[7][4]={"+",".join(array(bytes.fromhex(row["word_hex"]))
            for row in plan["runtime_rebase"]["words"])+"};",
        "static const u8 protected_bank_sha[32]="+array(bytes.fromhex(content["protected_bank"]["sha256"]))+";"]
    for name,row in packets.items():
        lines += ["static const u32 %s_packet_bytes=%d;" % (name,row["size"]),
                  "static const u8 %s_packet_sha[32]=%s;" % (name,array(bytes.fromhex(row["sha256"]))),
                  'static const char %s_packet_path[]="%s";' % (name,row["upload_path"])]
    return ("\n".join(lines)+"\n").encode()


def _save(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def _elf(raw):
    result=pin._validate_elf(raw)
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


def build_rebase_worker(plan, output, *, compiler=None):
    validate_runtime_rebase(plan)
    result={"schema":"a7m4-pin-rebase-worker-bundle/1","plan_id":plan["plan_id"],
        "content_plan_id":plan["content_plan"]["plan_id"],"worker_built":False,
        "status":"BLOCKED_COMPILER_UNAVAILABLE","device_io":False,"network_io":False,
        "device_execution_state":"HELD","blockers":[],
        "request":{"file":REQUEST_PATH,"bytes":64},"report":{"file":REPORT_PATH,"bytes":184}}
    if compiler is None:
        result["blockers"]=["Explicit offline Zig0.13.0 required; no download"]
        return result
    command=[os.fspath(compiler)] if isinstance(compiler,(str,os.PathLike)) else list(compiler)
    _need(command and all(type(x) is str and x for x in command),"Explicit compiler command required")
    canonical=Path(__file__).resolve().parents[2]/"native/pin-rebase/program.c"
    packaged=Path(__file__).with_name("data")/"pin-rebase.c"
    sources=[path for path in (packaged,canonical) if path.exists() or path.is_symlink()]
    _need(sources and all(path.is_file() and not path.is_symlink() and sha256(path.read_bytes()).hexdigest()==SOURCE_SHA256
          for path in sources),"Canonical/packaged runtime rebase source binding differs")
    directory=Path(output).absolute()
    _need(not directory.exists() and directory.parent.is_dir() and not any(path.is_symlink() for path in (directory,*directory.parents)),
          "New private runtime rebase build directory required")
    directory.mkdir(mode=0o700)
    packets=_packets(plan)
    for row in packets.values():_save(directory/row["file"],row["data"])
    result["packets"]={name:{key:value for key,value in row.items() if key!="data"} for name,row in packets.items()}
    result["output_dir"]=str(directory)
    header=render_header(plan,packets);_save(directory/"patch_manifest.h",header)
    _save(directory/"runtime-rebase.json",_canonical(plan)+b"\n")
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
        for name in ("pin-rebase.so","pin-rebase-repeat.so"):
            path=directory/name
            subprocess.run(common+flags+[str(sources[0]),"-o",str(path)],capture_output=True,check=True,timeout=180,env=env)
            path.chmod(0o600);raw=path.read_bytes()
            _need(0<len(raw)<65536,"Runtime rebase helper exceeds strict upload bound")
            _elf(raw);binaries.append(raw)
        _need(binaries[0]==binaries[1] and all(sha256(path.read_bytes()).hexdigest()==SOURCE_SHA256 for path in sources),
              "Runtime rebase build/source reproducibility failed")
        result.update(worker_built=True,status="BUILT_OFFLINE_NOT_DEVICE_VALIDATED",
            worker={"file":"pin-rebase.so","size":len(binaries[0]),"sha256":sha256(binaries[0]).hexdigest(),
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
