"""Return only the output created by this short-lived privileged job.

result_owner pins the private parent; create_job_output immediately pins its
new child. Two descriptor-relative passes validate and return the bounded tree
without keeping every file open or selecting a replacement root pathname.
No transport, shell, password handling or arbitrary recursive chown is provided.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import stat


class ResultDeliveryError(ValueError):
    """The result cannot be safely delivered at its expected path."""

    status = "STOPPED_RESULT_DELIVERY"

    def __init__(self, message, *, ownership_returned=False, partial=None):
        super().__init__(message)
        self.ownership_returned = ownership_returned
        self.result_delivery_confirmed = False
        if isinstance(partial, dict):
            self.result = {**partial, "status": self.status, "error": message,
                           "result_delivery_confirmed": False,
                           "ownership_returned": ownership_returned}


def _need(value, text):
    if not value:
        raise ValueError(text)


def _path(value):
    _need(isinstance(value, (str, os.PathLike)), "作业输出必须是本机目录路径。")
    path = Path(value).absolute()
    _need(".." not in path.parts and "\0" not in str(path), "作业目录不得包含路径跳转。")
    return path


def _real_parents(path):
    for item in (path, *path.parents):
        _need(not item.is_symlink(), "作业目录不得经过符号链接。")


def _identity(info):
    return info.st_dev, info.st_ino


def _absent(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
# Complete 73-file restore plus 32KiB chunk journals remain bounded without
# opening one FD per object. Capacity is independent of FD depth.
MAX_OBJECTS = 65536
_ACTIVE = ContextVar("a7m4_job_result_owner", default=None)


class _Scope:
    def __init__(self, path, uid, gid, parent):
        self.path, self.uid, self.gid, self.parent = path, uid, gid, parent
        self.parent_identity = _identity(os.fstat(parent))
        self.child = None
        self.child_identity = None
        self.creator_uid = None
        self.created = False
        self.creation_verified = False
        self.opened = []

    def parent_matches(self):
        try:
            _real_parents(self.path.parent)
            actual = self.path.parent.lstat()
            return (stat.S_ISDIR(actual.st_mode) and _identity(actual) == self.parent_identity
                    and actual.st_uid == self.uid and actual.st_gid == self.gid
                    and stat.S_IMODE(actual.st_mode) == 0o700)
        except (OSError, ValueError):
            return False

    def delivered(self):
        if not self.parent_matches():
            return False
        try:
            info = os.stat("capture", dir_fd=self.parent, follow_symlinks=False)
            return stat.S_ISDIR(info.st_mode) and _identity(info) == self.child_identity
        except OSError:
            return False

    def create(self, path):
        _need(path == self.path, "输出必须是当前所有权作业绑定的 capture 目录。")
        _need(not self.created and self.child is None, "本次作业只能创建一次输出目录。")
        _need(self.parent_matches(), "GUI 作业父目录在创建前已移动、替换或改变。")
        os.mkdir("capture", mode=0o700, dir_fd=self.parent)
        self.created = True
        created = os.stat("capture", dir_fd=self.parent, follow_symlinks=False)
        # Pin immediately; ownership return never reopens this name.
        self.child = os.open("capture", _DIR_FLAGS, dir_fd=self.parent)
        self.opened.append(self.child)
        info = os.fstat(self.child)
        self.child_identity = _identity(info)
        self.creator_uid = os.geteuid()
        _need(_identity(info) == _identity(created)
              and stat.S_ISDIR(info.st_mode) and info.st_uid == self.creator_uid
              and stat.S_IMODE(info.st_mode) == 0o700 and not os.listdir(self.child),
              "新作业目录的所有者、权限或初始内容不符。")
        self.creation_verified = True
        _need(self.delivered(), "新作业目录在创建时已被移动或替换。")
        return self.path

    @staticmethod
    def _signature(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _admit(self, info):
        directory = stat.S_ISDIR(info.st_mode)
        _need(directory or stat.S_ISREG(info.st_mode), "作业输出包含链接或特殊文件。")
        _need(info.st_dev == self.child_identity[0] and info.st_uid == self.creator_uid
              and (directory or info.st_nlink == 1),
              "作业输出所有权、文件系统或链接数发生变化。")
        return directory

    def _open_item(self, parent, name, expected):
        item = os.stat(name, dir_fd=parent, follow_symlinks=False)
        directory = self._admit(item)
        _need(self._signature(item) == expected, "作业输出在重新打开前发生变化。")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if directory else 0)
        fd = os.open(name, flags, dir_fd=parent)
        try:
            current = os.fstat(fd)
            _need(self._signature(current) == expected, "作业输出在打开时发生变化。")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def collect(self):
        """First pass validates the entire tree with only one FD per depth.

        Ordinary files close immediately. The in-memory inventory pins exact
        object identities/metadata, not thousands of open descriptors. The
        original capture FD remains held through delivery, including renames.
        """
        root = os.fstat(self.child)
        _need(_identity(root) == self.child_identity and root.st_uid == self.creator_uid
              and stat.S_IMODE(root.st_mode) == 0o700,
              "已固定的作业输出所有者或私有权限发生变化。")
        seen, count = {self.child_identity}, [1]

        def walk(fd, depth=0):
            _need(depth <= 8, "作业目录过深。")
            before = os.fstat(fd)
            # These are only new objects within the pinned, initially empty
            # private capture. Keep every directory inaccessible until its
            # children have been returned. Never chmod files or outside paths.
            if stat.S_IMODE(before.st_mode) != 0o700:
                os.fchmod(fd, 0o700)
                before = os.fstat(fd)
            children = {}
            for name in sorted(os.listdir(fd)):
                _need(count[0] < MAX_OBJECTS, "作业输出对象超过 %d 个。" % MAX_OBJECTS)
                item = os.stat(name, dir_fd=fd, follow_symlinks=False)
                directory = self._admit(item)
                identity = _identity(item)
                _need(identity not in seen, "作业输出包含重复文件身份。")
                seen.add(identity)
                count[0] += 1
                child = self._open_item(fd, name, self._signature(item))
                try:
                    if directory:
                        node = walk(child, depth + 1)
                    else:
                        node = {"signature": self._signature(os.fstat(child)), "children": None}
                        _need(node["signature"] == self._signature(item), "作业文件在校验时发生变化。")
                    children[name] = node
                finally:
                    os.close(child)
            _need(self._signature(os.fstat(fd)) == self._signature(before)
                  and set(os.listdir(fd)) == set(children), "作业目录在完整校验期间发生变化。")
            return {"signature": self._signature(before), "children": children}

        self.inventory = walk(self.child)

    def transfer(self):
        """Second pass reopens exact inventoried objects, returns postorder.

        The root stays creator-owned 0700 until all descendants finish. Thus a
        normal user cannot enter early-returned children and replace remaining
        objects. Each FD is rechecked immediately before fchown and closed;
        name/directory membership is checked before returning each directory.
        """
        def walk(fd, node):
            _need(self._signature(os.fstat(fd)) == node["signature"],
                  "归还前作业输出身份或内容发生变化。")
            children = node["children"]
            if children is not None:
                _need(set(os.listdir(fd)) == set(children), "归还前作业目录库存发生变化。")
                returned = {}
                for name, child_node in children.items():
                    child = self._open_item(fd, name, child_node["signature"])
                    try:
                        walk(child, child_node)
                        returned[name] = os.fstat(child)
                    finally:
                        os.close(child)
                _need(set(os.listdir(fd)) == set(children), "归还中作业目录库存发生变化。")
                for name, info in returned.items():
                    actual = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    _need(self._signature(actual) == self._signature(info),
                          "已归还的作业子对象在目录交接前发生变化。")
            _need(self._signature(os.fstat(fd)) == node["signature"],
                  "立即归还前作业输出发生变化。")
            _return_fd(fd, self.uid, self.gid)

        walk(self.child, self.inventory)

    def finish(self):
        if self.child is None:
            # Cancellation creates nothing. A legacy mkdir is never adopted.
            _need(not self.created and _absent(self.parent, "capture"),
                  "输出并非由 create_job_output 创建；未更改其所有权。")
            return
        _need(self.creation_verified, "初建输出身份未通过验证；未更改其所有权。")
        self.collect()
        self.transfer()
        if not self.delivered():
            raise ResultDeliveryError(
                "真实产物已按固定目录句柄归还，但原交付路径已被移动、替换或改变。",
                ownership_returned=True)

    def close(self):
        for fd in reversed(self.opened):
            os.close(fd)
        os.close(self.parent)


def _return_fd(fd, uid, gid):
    if os.geteuid() == 0:
        os.fchown(fd, uid, gid)


def create_job_output(path) -> Path:
    """Exclusively create new 0700 output and return its absolute Path.

    Within result_owner only its bound capture child can be created, using the
    pinned parent descriptor. Outside a scope this is ordinary local mkdir.
    Parents are not created, existing output is not adopted, links are refused.
    """
    path = _path(path)
    active = _ACTIVE.get()
    if active is not None:
        created=active.create(path)
        from .run_log import bind_job
        bind_job(created)
        return created
    _real_parents(path)
    _need(path.parent.is_dir(), "作业输出的父目录必须已经存在。")
    path.mkdir(mode=0o700)
    from .run_log import bind_job
    bind_job(path)
    return path


@contextmanager
def result_owner(output, uid=None, gid=None):
    """Bind newly created output to a user's private GUI job.

    Coordinators must use create_job_output for initial output creation.
    Cancellation needs no output. Partial output is returned even on failure.
    A moved result is returned through its pinned descriptor, then reported as
    STOPPED_RESULT_DELIVERY. Partial I/O evidence is preserved when available.
    """
    if uid is None and gid is None:
        yield
        return
    _need(type(uid) is int and type(gid) is int and uid >= 501 and gid >= 0,
          "作业所有者必须是明确的普通本机用户。")
    _need(_ACTIVE.get() is None, "不得嵌套提权输出所有权作业。")
    path = _path(output)
    _need(path.name == "capture", "提权备份输出必须是本次私有作业的 capture 子目录。")
    _real_parents(path)
    parent = os.open(path.parent, _DIR_FLAGS)
    scope = _Scope(path, uid, gid, parent)
    token = None
    try:
        info = os.fstat(parent)
        _need(info.st_uid == uid and info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o700,
              "GUI 作业目录必须由该用户持有且权限为 0700。")
        _need(scope.parent_matches(), "GUI 作业父目录在检查时已变化。")
        _need(_absent(parent, "capture"), "输出已存在；不更改现有文件的所有权。")
        _need(os.geteuid() in (0, uid), "当前进程无权归还作业所有权。")
        token = _ACTIVE.set(scope)
        failure = None
        try:
            yield
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                scope.finish()
            except (OSError, ValueError) as error:
                returned = isinstance(error, ResultDeliveryError) and error.ownership_returned
                delivery = ResultDeliveryError(str(error), ownership_returned=returned,
                                               partial=getattr(failure, "result", None))
                raise delivery from (failure if failure is not None else error)
    finally:
        if token is not None:
            _ACTIVE.reset(token)
        scope.close()
