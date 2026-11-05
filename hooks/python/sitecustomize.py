"""Delete Guard 运行时钩子（Python）。

由 DSH 的 shell 深度层通过 PYTHONPATH 注入；解释器启动时由 site 自动 import。
规则：删除类 API 的目标必须落在本次命令「已备份批准」的根内，或易失目录内；
否则抛 PermissionError 阻断（fail-closed）。

覆盖：os.remove / os.unlink / os.rmdir / os.removedirs / os.rename / os.replace /
      shutil.rmtree / pathlib.Path.unlink / pathlib.Path.rmdir。
"""

import json
import os
import sys

_ENV_ALLOW = "DSH_DELETE_GUARD_ALLOW"
_state = None
_loaded = False


def _load():
    global _state, _loaded
    if _loaded:
        return _state
    _loaded = True
    path = os.environ.get(_ENV_ALLOW)
    if not path:
        _state = ("deny", [], [], False, "缺少允许清单（fail-closed）")
        return _state
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        roots = [
            os.path.normcase(os.path.abspath(os.fspath(item)))
            for item in data.get("roots", [])
            if isinstance(item, str)
        ]
        volatile = [
            os.path.normcase(os.path.abspath(os.fspath(item)))
            for item in data.get("volatile", [])
            if isinstance(item, str)
        ]
        # 用户对「目标解析不出」的命令输入过确认码：整条命令放行。
        allow_all = data.get("allowAll") is True
        _state = ("allow", roots, volatile, allow_all, None)
    except Exception as error:  # noqa: BLE001
        _state = ("deny", [], [], False, str(error))
    return _state


def _inside(parent, child):
    if parent == child:
        return True
    if parent.endswith(os.sep):
        return child.startswith(parent)
    return child.startswith(parent + os.sep)


def _check(target, operation):
    mode, roots, volatile, allow_all, reason = _load()
    try:
        resolved = os.path.normcase(os.path.abspath(os.fspath(target)))
    except Exception as error:  # noqa: BLE001
        raise PermissionError("delete-guard: 无法解析删除目标（%s）" % (error,)) from error
    if mode == "deny":
        raise PermissionError("delete-guard: 拒绝删除 %s（%s）" % (resolved, reason))
    if allow_all:
        # 用户已对这条「目标无法解析」的命令确认放行。
        return
    for root in roots:
        if _inside(root, resolved):
            return
    for root in volatile:
        if _inside(root, resolved):
            return
    raise PermissionError(
        "delete-guard: 未审批的删除操作已阻断：%s（操作：%s）。"
        "目标不在本次命令已备份的范围内；如确需删除，请通过 DSH 工具重新发起，"
        "让 Delete Guard 先备份。" % (resolved, operation)
    )


def _wrap(module, name, factory):
    original = getattr(module, name, None)
    if original is None or getattr(original, "_delete_guard_wrapped", False):
        return
    wrapped = factory(original)
    try:
        wrapped._delete_guard_wrapped = True
    except Exception:  # noqa: BLE001
        pass
    setattr(module, name, wrapped)


def _wrap_path_1(op):
    def factory(original):
        def wrapper(path, *args, **kwargs):
            _check(path, op)
            return original(path, *args, **kwargs)

        return wrapper

    return factory


def _wrap_rename(original):
    def wrapper(src, dst, *args, **kwargs):
        _check(src, "rename")
        try:
            if os.path.exists(dst):
                _check(dst, "rename-overwrite")
        except OSError:
            pass
        return original(src, dst, *args, **kwargs)

    return wrapper


def _install():
    try:
        import shutil
    except Exception:  # noqa: BLE001
        shutil = None
    for name, op in (
        ("remove", "remove"),
        ("unlink", "unlink"),
        ("rmdir", "rmdir"),
        ("removedirs", "removedirs"),
    ):
        if hasattr(os, name):
            _wrap(os, name, _wrap_path_1(op))
    for name in ("rename", "replace"):
        if hasattr(os, name):
            _wrap(os, name, _wrap_rename)
    if shutil is not None and hasattr(shutil, "rmtree"):
        _wrap(shutil, "rmtree", _wrap_path_1("rmtree"))
    try:
        import pathlib
    except Exception:  # noqa: BLE001
        pathlib = None
    if pathlib is not None:
        for name, op in (("unlink", "unlink"), ("rmdir", "rmdir")):
            original = getattr(pathlib.Path, name, None)
            if original is None:
                continue

            def make(orig, operation):
                def wrapper(self, *args, **kwargs):
                    _check(str(self), operation)
                    return orig(self, *args, **kwargs)

                return wrapper

            wrapped = make(original, op)
            try:
                wrapped._delete_guard_wrapped = True
            except Exception:  # noqa: BLE001
                pass
            setattr(pathlib.Path, name, wrapped)


_install()
