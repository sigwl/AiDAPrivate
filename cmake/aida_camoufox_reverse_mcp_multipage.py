from __future__ import annotations

import ast
import pathlib
import re
import sys


ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
AIDA_INITIATOR_CONTRACT_V2 = "aida_initiator_contract_v2_page_marker"
AIDA_PLAYWRIGHT_PAGEERROR_PATCH_ID = "aida_playwright_pageerror_location_patch_20260620_1"
AIDA_DEFAULT_ADDON_POLICY_V1 = "aida_default_addon_policy_v1"
AIDA_FAST_VISIBLE_POLICY_V1 = "aida_fast_visible_policy_v1"
AIDA_CONTEXT_VIEWPORT_SANITIZER_V1 = "aida_context_viewport_sanitizer_v1"


def fail(message: str) -> None:
    raise SystemExit(f"AiDA Camoufox reverse MCP multipage patch failed: {message}")


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except FileNotFoundError:
        fail(f"missing {path}")


def write_text(path: pathlib.Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        fail(f"missing anchor {label}")
    return text.replace(old, new, 1)


def _resolved_numeric_assignments(tree: ast.Module) -> dict[str, int | float]:
    raw: dict[str, int | float | str] = {}
    for node in tree.body:
        target = None
        value = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
            value = node.value
        if not target or value is None:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, (int, float)):
            raw[target] = value.value
        elif isinstance(value, ast.Name):
            raw[target] = value.id
    resolved: dict[str, int | float] = {}

    def resolve(name: str, seen: set[str] | None = None) -> int | float | None:
        if name in resolved:
            return resolved[name]
        seen = set(seen or ())
        if name in seen:
            return None
        seen.add(name)
        value = raw.get(name)
        if isinstance(value, (int, float)):
            resolved[name] = value
            return value
        if isinstance(value, str):
            nested = resolve(value, seen)
            if nested is not None:
                resolved[name] = nested
            return nested
        return None

    for key in list(raw.keys()):
        resolve(key)
    return resolved


def validate_browser_launch_budget_contract(path: pathlib.Path, text: str) -> None:
    required_markers = (
        "AIDA_LAUNCH_BUDGET_POLICY_MARKER",
        "aida_launch_budget_policy_v1",
        "AIDA_LAUNCH_MAX_TIMEOUT_MS",
        "AIDA_LAUNCH_FLOOR_MS",
        "AIDA_LAUNCH_PHASE_POLICY",
        "def aida_resolve_launch_budget_policy",
        "def aida_validate_launch_budget_policy",
        "def aida_retry_launch_timeout_ms",
        "launch_budget_policy",
        "launch_budget_allocation",
    )
    for marker in required_markers:
        if marker not in text:
            fail(f"browser launch budget contract missing {marker} in {path}")
    forbidden_markers = (
        "page_create_timeout_s = min(18.0, max(8.0, launch_timeout_s * (0.18 if fast_probe else 0.24)), launch_timeout_s)",
        "late_page_wait_s = 1.0 if fast_probe else min(5.0, max(1.0, launch_timeout_s * 0.08))",
    )
    for marker in forbidden_markers:
        if marker in text:
            fail(f"browser launch budget contract regression detected ({marker}) in {path}")
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        fail(f"browser launch budget contract could not parse {path}: {exc}")
    assignments = _resolved_numeric_assignments(tree)
    max_ms = assignments.get("AIDA_LAUNCH_MAX_TIMEOUT_MS")
    floor_ms = assignments.get("AIDA_LAUNCH_FLOOR_MS")
    defaults = (
        assignments.get("AIDA_LAUNCH_DEFAULT_BUNDLED_VISIBLE_MS"),
        assignments.get("AIDA_LAUNCH_DEFAULT_FAST_PROBE_MS"),
        assignments.get("AIDA_LAUNCH_DEFAULT_NORMAL_MS"),
    )
    if max_ms is None or int(max_ms) > 40000:
        fail(f"browser launch budget policy max is missing or above 40000ms in {path}")
    if floor_ms is None or int(floor_ms) <= 0:
        fail(f"browser launch budget policy floor is missing or nonpositive in {path}")
    for value in defaults:
        if value is None or int(floor_ms) > int(value) or int(value) > int(max_ms):
            fail(f"browser launch budget policy default outside floor/max bounds in {path}")
    functions = {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for function_name in ("aida_resolve_launch_budget_policy", "aida_validate_launch_budget_policy", "aida_retry_launch_timeout_ms"):
        if function_name not in functions:
            fail(f"browser launch budget policy missing function {function_name} in {path}")
    if "async def _wait_for_late_page" not in text:
        fail(f"browser late page contract missing _wait_for_late_page in {path}")
    late_page_start = text.find("async def _wait_for_late_page")
    late_page_end = text.find("\n    def ", late_page_start + 1)
    if late_page_end < 0:
        late_page_end = text.find("\n    async def ", late_page_start + 1)
    if late_page_end < 0:
        late_page_end = len(text)
    late_page_body = text[late_page_start:late_page_end]
    if "self.pages" not in late_page_body:
        fail(f"browser late page contract missing self.pages reference in _wait_for_late_page in {path}")
    if 'source="self_pages"' not in late_page_body:
        fail(f"browser late page contract missing self_pages source tag in _wait_for_late_page in {path}")


def validate_browser_addon_policy_contract(path: pathlib.Path, text: str) -> None:
    required_markers = (
        AIDA_DEFAULT_ADDON_POLICY_V1,
        "DefaultAddons.UBO",
        "exclude_addons",
        "launch_options_addon_policy",
        "launch_options_addon_invalid",
        "default_exclusion_scope",
        "all_launches",
        "default_addons_excluded",
        "explicit_addon_count",
        "explicit_addons_validated",
    )
    for marker in required_markers:
        if marker not in text:
            fail(f"browser addon policy contract missing {marker} in {path}")
    if "if explicit_addon_count == 0:" in text:
        fail(f"browser addon policy contract has stale no-explicit-addon UBO exclusion gate in {path}")


def validate_browser_context_viewport_contract(path: pathlib.Path, text: str) -> None:
    required_markers = (
        AIDA_CONTEXT_VIEWPORT_SANITIZER_V1,
        "def _sanitize_camoufox_context_options",
        'sanitized["no_viewport"] = True',
        "_CONTEXT_VIEWPORT_DEVICE_KEYS",
        '"viewport"',
        '"screen"',
        '"device_scale_factor"',
        '"deviceScaleFactor"',
        '"is_mobile"',
        '"isMobile"',
        "page.set_viewport_size(target)",
        "page_viewport_set_ok",
        "protocol_schema_viewport",
        "browser.setdefaultviewport",
    )
    for marker in required_markers:
        if marker not in text.lower() and marker.lower() not in text.lower():
            fail(f"browser context viewport contract missing {marker} in {path}")
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        fail(f"browser context viewport contract could not parse {path}: {exc}")
    forbidden = {"viewport", "screen", "device_scale_factor", "deviceScaleFactor", "is_mobile", "isMobile"}
    safe_expansion_calls = {
        ("new_context", "_create_camoufox_safe_context"),
        ("new_context", "_create_private_context"),
        ("new_page", "_create_private_browser_page_context"),
    }
    violations = []
    function_stack: list[str] = []

    class ContextViewportVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"new_context", "new_page"}:
                owner = function_stack[-1] if function_stack else ""
                if func.attr == "new_context" and not node.keywords and (func.attr, owner) not in safe_expansion_calls:
                    violations.append(f"{func.attr}:direct:{getattr(node, 'lineno', 0)}:{owner}")
                for keyword in node.keywords:
                    if keyword.arg in forbidden:
                        violations.append(f"{func.attr}:{keyword.arg}:{getattr(node, 'lineno', 0)}")
                    elif keyword.arg is None and (func.attr, owner) not in safe_expansion_calls:
                        violations.append(f"{func.attr}:kwargs:{getattr(node, 'lineno', 0)}:{owner}")
            self.generic_visit(node)

    ContextViewportVisitor().visit(tree)
    if violations:
        fail(f"browser context viewport contract has direct context emulation keywords in {path}: {', '.join(violations[:8])}")


def replace_in_function(text: str, function_name: str, old: str, new: str, label: str) -> str:
    marker = f"async def {function_name}("
    start = text.find(marker)
    if start < 0:
        fail(f"missing function {function_name} for {label}")
    next_tool = text.find("\n\n@mcp.tool()", start + len(marker))
    if next_tool < 0:
        next_tool = len(text)
    block = text[start:next_tool]
    if old not in block:
        fail(f"missing anchor {label}")
    block = block.replace(old, new, 1)
    return text[:start] + block + text[next_tool:]


def patch_browser_debug_helper(text: str) -> str:
    if "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:" not in text:
        text = text.replace(
            "def _camoufox_debug(event: str, **fields: Any) -> None:",
            "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:",
            1,
        )
    if "payload = {\"event\": event, **fields}" in text:
        text = text.replace(
            "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:\n"
            "    payload = {\"event\": event, **fields}\n",
            "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:\n"
            "    safe_fields = dict(fields)\n"
            "    if \"event\" in safe_fields:\n"
            "        safe_fields[\"payload_event\"] = safe_fields.pop(\"event\")\n"
            "    payload = {\"event\": event_name, **safe_fields}\n",
            1,
        )
    if "payload = {\"event\": event_name, **fields}" in text:
        text = text.replace(
            "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:\n"
            "    payload = {\"event\": event_name, **fields}\n",
            "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:\n"
            "    safe_fields = dict(fields)\n"
            "    if \"event\" in safe_fields:\n"
            "        safe_fields[\"payload_event\"] = safe_fields.pop(\"event\")\n"
            "    payload = {\"event\": event_name, **safe_fields}\n",
            1,
        )
    if "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:\n    payload = {\n" in text and "safe_fields = dict(fields)" not in text:
        text = text.replace(
            "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:\n"
            "    payload = {\n",
            "def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:\n"
            "    safe_fields = dict(fields)\n"
            "    if \"event\" in safe_fields:\n"
            "        safe_fields[\"payload_event\"] = safe_fields.pop(\"event\")\n"
            "    payload = {\n",
            1,
        )
    text = text.replace("\"event\": event,", "\"event\": event_name,", 1)
    if "payload.update(fields)" in text and "safe_fields = dict(fields)" in text:
        text = text.replace("    payload.update(fields)\n", "    payload.update(safe_fields)\n", 1)
    for marker in ("def _camoufox_debug(event_name: str = \"\", **fields: Any) -> None:", "payload_event"):
        if marker not in text:
            fail(f"browser debug helper validation missing {marker}")
    if "payload.update(fields)" in text or "\"event\": event," in text or "def _camoufox_debug(event: str" in text:
        fail("browser debug helper validation found unsafe event field handling")
    return text


def patch_browser_pending_activation(text: str) -> str:
    text = text.replace(
        "        self._pending_page_ids_by_context: dict[str, list[str]] = {}\n",
        "        self._pending_page_ids_by_context: dict[str, list[dict[str, Any]]] = {}\n",
    )
    text = text.replace(
        "            ctx.on(\"page\", lambda page, cid=context_id: self._register_page(page, self._pop_pending_page_id(cid), True, \"context_page\", cid))\n",
        "            ctx.on(\"page\", lambda page, cid=context_id: self._register_pending_context_page(page, cid))\n",
    )
    text = text.replace(
        "            ctx.on(\"page\", lambda page, cid=context_id: self._register_page(page, None, True, \"context_page\", cid))\n",
        "            ctx.on(\"page\", lambda page, cid=context_id: self._register_pending_context_page(page, cid))\n",
    )
    queue_block = '''    def _queue_pending_page_id(self, context_id: str, page_id: str | None, make_active: bool = True) -> None:
        pid = self._slug(page_id) if page_id else ""
        if pid:
            cid = context_id or "default"
            queue = self._pending_page_ids_by_context.setdefault(cid, [])
            queued_ms = int(time.time() * 1000)
            queue.append({"page_id": pid, "make_active": bool(make_active), "queued_ms": queued_ms})
            ctx = self.contexts.get(cid)
            pending_page_ids = [
                str(entry.get("page_id") if isinstance(entry, dict) else entry)
                for entry in queue
            ]
            _camoufox_debug(
                "pending_page_queued",
                session_id=self.session_id,
                context_id=cid,
                page_id=pid,
                make_active=bool(make_active),
                queued_ms=queued_ms,
                queue_len=len(queue),
                pending_queue_len=len(queue),
                pending_page_ids=pending_page_ids,
                context_page_count=_context_page_count(ctx),
                registered_pages=len(self.pages),
                registered_contexts=len(self.contexts),
                listener_page_ids=len(self._listener_page_ids),
                browser_open=self.browser is not None,
                browser_connected=self._browser_connected(),
                process_tree=_process_tree_snapshot(),
            )

    def _pop_pending_page_id(self, context_id: str) -> dict[str, Any]:
        cid = context_id or "default"
        queue = self._pending_page_ids_by_context.get(cid)
        if not queue:
            return {"page_id": None, "make_active": True}
        pending = queue.pop(0)
        if not queue:
            self._pending_page_ids_by_context.pop(cid, None)
        if isinstance(pending, dict):
            return {"page_id": pending.get("page_id"), "make_active": bool(pending.get("make_active", True))}
        return {"page_id": pending, "make_active": True}

    def _discard_pending_page_id(self, context_id: str, page_id: str | None) -> None:
        pid = self._slug(page_id) if page_id else ""
        cid = context_id or "default"
        queue = self._pending_page_ids_by_context.get(cid)
        if not pid or not queue:
            return
        before = len(queue)
        queue[:] = [entry for entry in queue if str(entry.get("page_id") if isinstance(entry, dict) else entry) != pid]
        if not queue:
            self._pending_page_ids_by_context.pop(cid, None)
        if len(queue) != before:
            _camoufox_debug(
                "pending_page_discarded",
                session_id=self.session_id,
                context_id=cid,
                page_id=pid,
                removed=before - len(queue),
                queue_len=len(queue),
            )

    def _register_pending_context_page(self, page: Page, context_id: str) -> str:
        pending = self._pop_pending_page_id(context_id)
        preferred_id = pending.get("page_id") if isinstance(pending, dict) else None
        make_active = bool(pending.get("make_active", True)) if isinstance(pending, dict) else True
        pid = self._register_page(page, preferred_id, make_active, "context_page", context_id)
        _camoufox_debug(
            "pending_context_page_registered",
            session_id=self.session_id,
            context_id=context_id or "default",
            requested_page_id=preferred_id or "",
            page_id=pid,
            make_active=make_active,
            active_page_id=self.active_page_id or "",
            page_count=len(self.pages),
        )
        return pid

'''
    patterns = (
        r"    def _queue_pending_page_id\(self, context_id: str, page_id: str \| None(?:, make_active: bool = True)?\) -> None:\n.*?(?=    def _first_live_page)",
        r"    def _queue_pending_page_id\(self, context_id: str, page_id: str \| None(?:, make_active: bool = True)?\) -> None:\n.*?(?=    def _register_page)",
    )
    for pattern in patterns:
        text, count = re.subn(pattern, queue_block, text, count=1, flags=re.S)
        if count:
            break
    if "self._queue_pending_page_id(requested_context_id, page_id)" in text:
        text = text.replace("self._queue_pending_page_id(requested_context_id, page_id)", "self._queue_pending_page_id(requested_context_id, page_id, make_active)")
    for marker in ("_register_pending_context_page", "pending_context_page_registered", "dict[str, list[dict[str, Any]]]", "self._queue_pending_page_id(requested_context_id, page_id, make_active)"):
        if marker not in text:
            fail(f"browser pending activation validation missing {marker}")
    if "self._pop_pending_page_id(cid), True, \"context_page\"" in text:
        fail("browser pending activation validation found forced active context page")
    return text


def patch_browser_new_page_diagnostics(text: str) -> str:
    block = '''    async def new_page(self, url: str | None = None, page_id: str | None = None, make_active: bool = True, context_id: str | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        await self._ensure_browser()
        requested_context_id = context_id or "default"
        ctx = self.contexts.get(requested_context_id) or await self.get_active_context()
        requested_context_id = context_id or self.context_ids.get(id(ctx), "default")
        requested_page_id = self._slug(page_id) if page_id else ""
        page_create_timeout_s = 25.0

        def _pending_snapshot() -> list[dict[str, Any]]:
            queue = self._pending_page_ids_by_context.get(requested_context_id, [])
            out: list[dict[str, Any]] = []
            for entry in queue:
                if isinstance(entry, dict):
                    out.append(dict(entry))
                else:
                    out.append({"page_id": str(entry), "make_active": True})
            return out

        def _page_creation_snapshot(extra: dict[str, Any] | None = None) -> dict[str, Any]:
            pending = _pending_snapshot()
            snapshot: dict[str, Any] = {
                "session_id": self.session_id,
                "context_id": requested_context_id,
                "requested_page_id": requested_page_id,
                "make_active": bool(make_active),
                "url_len": len(url or ""),
                "elapsed_ms": int((time.perf_counter() - started) * 1000),
                "pending_queue_len": len(pending),
                "pending_page_ids": [str(item.get("page_id") or "") for item in pending],
                "context_page_count": _context_page_count(ctx),
                "registered_pages": len(self.pages),
                "registered_contexts": len(self.contexts),
                "active_page_id": self.active_page_id or "",
                "browser_open": self.browser is not None,
                "browser_connected": self._browser_connected(),
                "event_listener_state": {
                    "context_registered": requested_context_id in self.contexts,
                    "listener_page_ids": len(self._listener_page_ids),
                    "page_event_listener_expected": ctx is not None,
                    "close_event_handler": hasattr(self, "_handle_context_close_event"),
                    "page_terminal_ids": len(getattr(self, "_page_terminal_ids", set())),
                },
                "process_tree": _process_tree_snapshot(),
            }
            if extra:
                snapshot.update(extra)
            return snapshot

        async def _finalize_page(page: Page, source: str) -> dict[str, Any]:
            privacy_info = await _verify_page_privacy(page, self._context_plan)
            privacy_page_id = self.page_id_for(page) or (page_id or "")
            _camoufox_debug("page_privacy_verified", session_id=self.session_id, page_id=privacy_page_id, source=source, **privacy_info)
            if not privacy_info.get("webrtc_blocked") or not privacy_info.get("ice_probe_ok") or privacy_info.get("ice_candidate_leak_detected"):
                with contextlib.suppress(Exception):
                    await page.close()
                raise RuntimeError("Camoufox privacy verification failed")
            pid = self._register_page(page, page_id, make_active, source, requested_context_id)
            self._discard_pending_page_id(requested_context_id, page_id)
            if url:
                await page.goto(url, wait_until="load", timeout=30000)
            summary = await self.page_summary(page, pid)
            diagnostics = _page_creation_snapshot({"page_id": pid, "source": source})
            _camoufox_debug("page_created", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id or "", url_len=len(summary.get("url", "")), page_count=len(self.pages), source=source, diagnostics=diagnostics)
            return {"status": "created", "page": summary, "page_id": pid, "active_page_id": self.active_page_id, "page_count": len(self.pages), "diagnostics": diagnostics}

        self._queue_pending_page_id(requested_context_id, page_id, make_active)
        page_task = asyncio.create_task(ctx.new_page())
        page_task_id = id(page_task)
        begin_diag = _page_creation_snapshot({"page_task_id": page_task_id, "timeout_ms": int(page_create_timeout_s * 1000)})
        _camoufox_debug("new_page_begin", **begin_diag)
        try:
            _camoufox_debug("new_page_await_begin", **_page_creation_snapshot({"page_task_id": page_task_id, "timeout_ms": int(page_create_timeout_s * 1000)}))
            page = await asyncio.wait_for(asyncio.shield(page_task), timeout=page_create_timeout_s)
            return await _finalize_page(page, "new_page")
        except asyncio.TimeoutError:
            timeout_diag = _page_creation_snapshot({
                "page_task_id": page_task_id,
                "pending_page_task": not page_task.done(),
                "page_task_done": page_task.done(),
                "page_task_cancelled": page_task.cancelled(),
                "timeout_ms": int(page_create_timeout_s * 1000),
                "phase": "page_creation_timeout",
            })
            _camoufox_debug("new_page_timeout", **timeout_diag)
            late_result: dict[str, Any] | None = None
            late_page_status: dict[str, Any] = {"polls": 0, "task_completed": False, "candidate_seen": False, "registered": False}
            for poll_index in range(8):
                late_page_status["polls"] = poll_index + 1
                if page_task.done():
                    late_page_status["task_completed"] = True
                    if page_task.cancelled():
                        late_page_status["task_cancelled"] = True
                        late_page_status["error_type"] = "CancelledError"
                        late_page_status["error"] = "page creation task cancelled"
                        _camoufox_debug("new_page_late_task_cancelled", **_page_creation_snapshot({"page_task_id": page_task_id, "error_type": "CancelledError", "error_summary": "page creation task cancelled"}))
                        break
                    try:
                        late_page = page_task.result()
                        late_result = await _finalize_page(late_page, "new_page_late_task")
                        late_page_status["registered"] = True
                        late_page_status["page_id"] = late_result.get("page_id", "")
                        break
                    except asyncio.CancelledError:
                        late_page_status["task_cancelled"] = True
                        late_page_status["error_type"] = "CancelledError"
                        late_page_status["error"] = "page creation task cancelled"
                        _camoufox_debug("new_page_late_task_cancelled", **_page_creation_snapshot({"page_task_id": page_task_id, "error_type": "CancelledError", "error_summary": "page creation task cancelled"}))
                        break
                    except Exception as exc:
                        late_page_status["error_type"] = type(exc).__name__
                        late_page_status["error"] = _safe_text(exc, 700)
                        _camoufox_debug("new_page_late_task_exception", **_page_creation_snapshot({"page_task_id": page_task_id, "error_type": type(exc).__name__, "error_summary": _safe_text(exc, 700)}))
                        break
                for candidate in list(getattr(ctx, "pages", []) or []):
                    if candidate in self.pages.values():
                        continue
                    if self._page_closed(candidate):
                        continue
                    late_page_status["candidate_seen"] = True
                    try:
                        late_result = await _finalize_page(candidate, "new_page_late_context_scan")
                        late_page_status["registered"] = True
                        late_page_status["page_id"] = late_result.get("page_id", "")
                        break
                    except Exception as exc:
                        late_page_status["error_type"] = type(exc).__name__
                        late_page_status["error"] = _safe_text(exc, 700)
                        _camoufox_debug("new_page_late_candidate_exception", **_page_creation_snapshot({"page_task_id": page_task_id, "error_type": type(exc).__name__, "error_summary": _safe_text(exc, 700)}))
                        break
                if late_result is not None or late_page_status.get("error"):
                    break
                await asyncio.sleep(0.25)
            if late_result is not None:
                late_result.setdefault("diagnostics", {})["late_page_status"] = late_page_status
                _camoufox_debug("new_page_late_page_registered", **_page_creation_snapshot({"page_task_id": page_task_id, "late_page_status": late_page_status}))
                return late_result
            page_task.cancel()
            cleanup_cancelled = page_task.cancelled()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await page_task
            self._discard_pending_page_id(requested_context_id, page_id)
            cleanup_diag = _page_creation_snapshot({
                "page_task_id": page_task_id,
                "pending_page_task": not page_task.done(),
                "page_task_done": page_task.done(),
                "page_task_cancelled": page_task.cancelled() or cleanup_cancelled,
                "late_page_status": late_page_status,
                "cleanup_cancel_requested": True,
                "phase": "page_creation_timeout",
            })
            _camoufox_debug("new_page_cleanup_done", **cleanup_diag)
            return {
                "error": "new_page timed out waiting for Camoufox page creation",
                "status": "timeout",
                "phase": "page_creation_timeout",
                "timeout_phase": "page_creation_timeout",
                "sidecar_timeout_phase": "page_creation_timeout",
                "page_id": requested_page_id,
                "requested_page_id": requested_page_id,
                "context_id": requested_context_id,
                "pending_page_task": cleanup_diag.get("pending_page_task"),
                "pending_queue_len": cleanup_diag.get("pending_queue_len"),
                "context_page_count": cleanup_diag.get("context_page_count"),
                "registered_pages": cleanup_diag.get("registered_pages"),
                "page_task_id": page_task_id,
                "late_page_status": late_page_status,
                "cleanup_results": cleanup_diag,
                "diagnostics": cleanup_diag,
            }
        except Exception as exc:
            self._discard_pending_page_id(requested_context_id, page_id)
            exc_diag = _page_creation_snapshot({
                "page_task_id": page_task_id,
                "pending_page_task": not page_task.done(),
                "page_task_done": page_task.done(),
                "page_task_cancelled": page_task.cancelled(),
                "phase": "page_creation",
                "error_type": type(exc).__name__,
                "error": _safe_text(exc, 1000),
            })
            _camoufox_debug("new_page_exception", **exc_diag)
            return {
                "error": _safe_text(exc, 1000),
                "status": "error",
                "phase": "page_creation",
                "page_id": requested_page_id,
                "requested_page_id": requested_page_id,
                "context_id": requested_context_id,
                "error_type": type(exc).__name__,
                "pending_page_task": exc_diag.get("pending_page_task"),
                "pending_queue_len": exc_diag.get("pending_queue_len"),
                "context_page_count": exc_diag.get("context_page_count"),
                "registered_pages": exc_diag.get("registered_pages"),
                "page_task_id": page_task_id,
                "diagnostics": exc_diag,
            }

'''
    pattern = r"    async def new_page\(self, url: str \| None = None, page_id: str \| None = None, make_active: bool = True, context_id: str \| None = None\) -> dict\[str, Any\]:\n.*?(?=    async def select_page)"
    text, count = re.subn(pattern, block, text, count=1, flags=re.S)
    if count != 1:
        fail("browser new_page diagnostics anchor missing")
    for marker in ("new_page_timeout", "page_task_id", "page_creation_timeout", "new_page_cleanup_done", "new_page_late_page_registered", "new_page_late_task_cancelled"):
        if marker not in text:
            fail(f"browser new_page diagnostics validation missing {marker}")
    return text


def patch_navigation_reset_cleanup(path: pathlib.Path, text: str) -> str:
    if "from ..browser import _camoufox_debug" not in text:
        if "from ..browser import _safe_text, _target_domain\n" in text:
            text = text.replace("from ..browser import _safe_text, _target_domain\n", "from ..browser import _camoufox_debug, _safe_text, _target_domain\n", 1)
        elif "from ..server import mcp, browser_manager\n" in text:
            text = text.replace("from ..server import mcp, browser_manager\n", "from ..server import mcp, browser_manager\nfrom ..browser import _camoufox_debug, _safe_text\n", 1)
        else:
            fail(f"navigation debug import anchor missing {path}")
    elif "_safe_text" not in text.split("from ..browser import", 1)[1].split("\n", 1)[0]:
        text = text.replace("from ..browser import _camoufox_debug\n", "from ..browser import _camoufox_debug, _safe_text\n", 1)
    if "close_page_prefix: str | None = None" not in text:
        text = replace_once(
            text,
            "    clear_storage: bool = False,\n"
            ") -> dict:\n",
            "    clear_storage: bool = False,\n"
            "    close_page_prefix: str | None = None,\n"
            "    restore_page_id: str | None = None,\n"
            "    close_empty_contexts: bool = True,\n"
            ") -> dict:\n",
            "navigation reset cleanup signature",
        )
    if "reset_browser_state_complete" not in text:
        text = replace_in_function(
            text,
            "reset_browser_state",
            "    result: dict[str, Any] = {\"status\": \"reset\"}\n"
            "    try:\n",
            "    result: dict[str, Any] = {\"status\": \"reset\"}\n"
            "    try:\n"
            "        result[\"active_page_before\"] = getattr(browser_manager, \"active_page_id\", None)\n"
            "        result[\"page_count_before\"] = len(getattr(browser_manager, \"pages\", {}) or {})\n"
            "        result[\"context_count_before\"] = len(getattr(browser_manager, \"contexts\", {}) or {})\n",
            "navigation reset state snapshot",
        )
        text = replace_in_function(
            text,
            "reset_browser_state",
            "        return result\n"
            "    except Exception as e:\n"
            "        return {\"error\": str(e)}\n",
            "        if close_page_prefix:\n"
            "            prefix = str(close_page_prefix)\n"
            "            closed_pages: list[dict[str, Any]] = []\n"
            "            close_errors: list[dict[str, Any]] = []\n"
            "            page_ids = [\n"
            "                pid for pid in list(getattr(browser_manager, \"pages\", {}) or {})\n"
            "                if str(pid).startswith(prefix)\n"
            "            ]\n"
            "            for pid in page_ids:\n"
            "                try:\n"
            "                    close_result = await browser_manager.close_page(str(pid))\n"
            "                    closed_pages.append({\n"
            "                        \"page_id\": str(pid),\n"
            "                        \"status\": close_result.get(\"status\") if isinstance(close_result, dict) else \"\",\n"
            "                        \"active_page_id\": close_result.get(\"active_page_id\") if isinstance(close_result, dict) else None,\n"
            "                    })\n"
            "                except Exception as e:\n"
            "                    close_errors.append({\n"
            "                        \"page_id\": str(pid),\n"
            "                        \"error_type\": type(e).__name__,\n"
            "                        \"error\": _safe_text(e, 500),\n"
            "                    })\n"
            "            result[\"closed_pages\"] = closed_pages\n"
            "            result[\"close_page_prefix\"] = prefix\n"
            "            if close_errors:\n"
            "                result[\"close_page_errors\"] = close_errors\n"
            "        if close_empty_contexts:\n"
            "            closed_contexts: list[str] = []\n"
            "            context_errors: list[dict[str, Any]] = []\n"
            "            for cid, ctx in list((getattr(browser_manager, \"contexts\", {}) or {}).items()):\n"
            "                if str(cid) == \"default\":\n"
            "                    continue\n"
            "                try:\n"
            "                    live_pages = [\n"
            "                        page for page in list(getattr(ctx, \"pages\", []) or [])\n"
            "                        if not browser_manager._page_closed(page)\n"
            "                    ]\n"
            "                    if live_pages:\n"
            "                        continue\n"
            "                    await ctx.close()\n"
            "                    browser_manager._handle_context_close_event(str(cid), ctx)\n"
            "                    closed_contexts.append(str(cid))\n"
            "                except Exception as e:\n"
            "                    context_errors.append({\n"
            "                        \"context_id\": str(cid),\n"
            "                        \"error_type\": type(e).__name__,\n"
            "                        \"error\": _safe_text(e, 500),\n"
            "                    })\n"
            "            result[\"closed_contexts\"] = closed_contexts\n"
            "            if context_errors:\n"
            "                result[\"close_context_errors\"] = context_errors\n"
            "        if restore_page_id:\n"
            "            try:\n"
            "                restore_result = await browser_manager.select_page(str(restore_page_id))\n"
            "                result[\"restored_page_id\"] = restore_result.get(\"page_id\", restore_page_id) if isinstance(restore_result, dict) else restore_page_id\n"
            "            except Exception as e:\n"
            "                result[\"restore_page_error\"] = {\n"
            "                    \"page_id\": str(restore_page_id),\n"
            "                    \"error_type\": type(e).__name__,\n"
            "                    \"error\": _safe_text(e, 500),\n"
            "                }\n"
            "        result[\"active_page_after\"] = getattr(browser_manager, \"active_page_id\", None)\n"
            "        result[\"page_count_after\"] = len(getattr(browser_manager, \"pages\", {}) or {})\n"
            "        result[\"context_count_after\"] = len(getattr(browser_manager, \"contexts\", {}) or {})\n"
            "        _camoufox_debug(\n"
            "            \"reset_browser_state_complete\",\n"
            "            close_page_prefix=str(close_page_prefix or \"\"),\n"
            "            restore_page_id=str(restore_page_id or \"\"),\n"
            "            active_page_before=str(result.get(\"active_page_before\") or \"\"),\n"
            "            active_page_after=str(result.get(\"active_page_after\") or \"\"),\n"
            "            page_count_before=int(result.get(\"page_count_before\") or 0),\n"
            "            page_count_after=int(result.get(\"page_count_after\") or 0),\n"
            "            context_count_before=int(result.get(\"context_count_before\") or 0),\n"
            "            context_count_after=int(result.get(\"context_count_after\") or 0),\n"
            "            closed_pages=len(result.get(\"closed_pages\") or []),\n"
            "            closed_contexts=len(result.get(\"closed_contexts\") or []),\n"
            "            close_page_errors=len(result.get(\"close_page_errors\") or []),\n"
            "            close_context_errors=len(result.get(\"close_context_errors\") or []),\n"
            "            restore_failed=bool(result.get(\"restore_page_error\")),\n"
            "        )\n"
            "        return result\n"
            "    except Exception as e:\n"
            "        _camoufox_debug(\"reset_browser_state_exception\", error_type=type(e).__name__, error_summary=_safe_text(e, 800))\n"
            "        return {\"error\": str(e)}\n",
            "navigation reset cleanup body",
        )
    for marker in ("close_page_prefix: str | None = None", "reset_browser_state_complete", "closed_contexts"):
        if marker not in text:
            fail(f"navigation reset cleanup validation missing {marker} in {path}")
    return text


def patch_main(path: pathlib.Path) -> None:
    if not path.exists():
        return
    text = read_text(path)
    required_contract_markers = (
        "AIDA_INITIATOR_CONTRACT_V2",
        "--aida-contract-check",
        "AIDA_CONTEXT_VIEWPORT_SANITIZER",
        "context_viewport_sanitizer_ok",
        "direct_context_viewport_emulation_absent",
        "direct_context_viewport_emulation_violations",
        "safe_expansion_context_creation_present",
    )
    if all(marker in text for marker in required_contract_markers):
        return
    probe = f'''import sys as _aida_contract_sys
if "--aida-contract-check" in _aida_contract_sys.argv:
    import ast as _aida_contract_ast
    import inspect as _aida_contract_inspect
    import importlib.util as _aida_contract_importlib_util
    import json as _aida_contract_json
    AIDA_INITIATOR_CONTRACT_V2 = "{AIDA_INITIATOR_CONTRACT_V2}"
    AIDA_CONTEXT_VIEWPORT_SANITIZER_V1 = "{AIDA_CONTEXT_VIEWPORT_SANITIZER_V1}"
    try:
        from .tools import network as _aida_contract_network
        _aida_contract_fn = _aida_contract_network.get_request_initiator
        _aida_contract_sig = _aida_contract_inspect.signature(_aida_contract_fn)
        _aida_contract_params = list(_aida_contract_sig.parameters)
        _aida_contract_consts = repr(getattr(getattr(_aida_contract_fn, "__code__", None), "co_consts", ()))
        _aida_contract_ok = all(name in _aida_contract_params for name in ("request_id", "page_id", "marker")) and AIDA_INITIATOR_CONTRACT_V2 in _aida_contract_consts
        _aida_browser_spec = _aida_contract_importlib_util.find_spec("camoufox_reverse_mcp.browser")
        _aida_browser_text = ""
        if _aida_browser_spec and _aida_browser_spec.origin:
            with open(_aida_browser_spec.origin, "r", encoding="utf-8") as _aida_browser_handle:
                _aida_browser_text = _aida_browser_handle.read()
        _aida_context_markers_ok = all(marker in _aida_browser_text for marker in (
            AIDA_CONTEXT_VIEWPORT_SANITIZER_V1,
            "def _sanitize_camoufox_context_options",
            "page.set_viewport_size(target)",
            "page_viewport_set_ok",
            "protocol_schema_viewport",
            'sanitized["no_viewport"] = True',
        ))
        _aida_context_violations = []
        _aida_safe_expansion_calls = {{
            ("new_context", "_create_camoufox_safe_context"),
            ("new_context", "_create_private_context"),
            ("new_page", "_create_private_browser_page_context"),
        }}
        _aida_safe_expansion_seen = set()
        if _aida_browser_text:
            _aida_tree = _aida_contract_ast.parse(_aida_browser_text)
            _aida_forbidden = {{"viewport", "screen", "device_scale_factor", "deviceScaleFactor", "is_mobile", "isMobile"}}
            _aida_function_stack = []
            class _AidaContextViewportVisitor(_aida_contract_ast.NodeVisitor):
                def visit_FunctionDef(self, _aida_node):
                    _aida_function_stack.append(_aida_node.name)
                    self.generic_visit(_aida_node)
                    _aida_function_stack.pop()
                def visit_AsyncFunctionDef(self, _aida_node):
                    _aida_function_stack.append(_aida_node.name)
                    self.generic_visit(_aida_node)
                    _aida_function_stack.pop()
                def visit_Call(self, _aida_node):
                    _aida_func = _aida_node.func
                    if isinstance(_aida_func, _aida_contract_ast.Attribute) and _aida_func.attr in {{"new_context", "new_page"}}:
                        _aida_owner = _aida_function_stack[-1] if _aida_function_stack else ""
                        if _aida_func.attr == "new_context" and not _aida_node.keywords and (_aida_func.attr, _aida_owner) not in _aida_safe_expansion_calls:
                            _aida_context_violations.append({{"call": _aida_func.attr, "keyword": "direct", "line": getattr(_aida_node, "lineno", 0), "owner": _aida_owner}})
                        for _aida_keyword in _aida_node.keywords:
                            if _aida_keyword.arg in _aida_forbidden:
                                _aida_context_violations.append({{"call": _aida_func.attr, "keyword": _aida_keyword.arg, "line": getattr(_aida_node, "lineno", 0), "owner": _aida_owner}})
                            elif _aida_keyword.arg is None:
                                _aida_pair = (_aida_func.attr, _aida_owner)
                                if _aida_pair in _aida_safe_expansion_calls:
                                    _aida_safe_expansion_seen.add(_aida_pair)
                                else:
                                    _aida_context_violations.append({{"call": _aida_func.attr, "keyword": "kwargs", "line": getattr(_aida_node, "lineno", 0), "owner": _aida_owner}})
                    self.generic_visit(_aida_node)
            _AidaContextViewportVisitor().visit(_aida_tree)
        _aida_safe_expansion_ok = all(_aida_pair in _aida_safe_expansion_seen for _aida_pair in _aida_safe_expansion_calls)
        _aida_context_ok = _aida_context_markers_ok and _aida_safe_expansion_ok and not _aida_context_violations
        _aida_ok = _aida_contract_ok and _aida_context_ok
        print(_aida_contract_json.dumps({{"runtime_marker": "AIDA_CAMOUFOX_RUNTIME_CONTRACT_OK", "contract": AIDA_INITIATOR_CONTRACT_V2, "ok": _aida_ok, "initiator_params": _aida_contract_params, "has_marker_constant": AIDA_INITIATOR_CONTRACT_V2 in _aida_contract_consts, "context_viewport_sanitizer_marker": AIDA_CONTEXT_VIEWPORT_SANITIZER_V1, "context_viewport_sanitizer_ok": _aida_context_ok, "context_viewport_markers_ok": _aida_context_markers_ok, "direct_context_viewport_emulation_absent": not _aida_context_violations, "direct_context_viewport_emulation_violations": _aida_context_violations, "safe_expansion_context_creation_present": _aida_safe_expansion_ok, "safe_expansion_context_creation_seen": sorted(":".join(_aida_pair) for _aida_pair in _aida_safe_expansion_seen)}}, sort_keys=True))
        raise SystemExit(0 if _aida_ok else 2)
    except Exception as _aida_contract_exc:
        print(_aida_contract_json.dumps({{"runtime_marker": "AIDA_CAMOUFOX_RUNTIME_CONTRACT_OK", "contract": AIDA_INITIATOR_CONTRACT_V2, "ok": False, "initiator_params": [], "error_type": type(_aida_contract_exc).__name__, "error": str(_aida_contract_exc)[:500]}}, sort_keys=True))
        raise SystemExit(3)

'''
    insert_pos = 0
    for match in re.finditer(r"from __future__ import [^\n]+\n", text):
        if match.start() == insert_pos:
            insert_pos = match.end()
        else:
            break
    write_text(path, text[:insert_pos] + probe + text[insert_pos:])


def validate_playwright_pageerror_patch(base: pathlib.Path) -> None:
    main_path = base / "__main__.py"
    patch_path = base / "_playwright_patch.py"
    if not main_path.exists():
        fail(f"main source missing {main_path}")
    if not patch_path.exists():
        fail(f"Playwright pageError patch source missing {patch_path}")
    main_text = read_text(main_path)
    patch_text = read_text(patch_path)
    for marker in (
        "_aida_apply_playwright_pageerror_patch",
        "patch_playwright_pageerror",
        "playwright_patch=playwright_patch",
    ):
        if marker not in main_text:
            fail(f"main source validation missing {marker} in {main_path}")
    for marker in (
        "AIDA_PLAYWRIGHT_PAGEERROR_PATCH_ID",
        AIDA_PLAYWRIGHT_PAGEERROR_PATCH_ID,
        "patch_playwright_pageerror",
        "coreBundle.js",
        "pageError.location.url",
        "pageError.location?.url ?? ''",
        "pageError.location.lineNumber",
        "pageError.location?.lineNumber ?? 0",
        "pageError.location.columnNumber",
        "pageError.location?.columnNumber ?? 0",
    ):
        if marker not in patch_text:
            fail(f"Playwright pageError patch validation missing {marker} in {patch_path}")


def replace_browser_already_running_summary(text: str) -> str:
    pattern = re.compile(
        r'(?P<i>[ \t]+)pages_info = \{\}\n'
        r'(?P=i)for name, p in self\.pages\.items\(\):\n'
        r'(?P=i)    try:\n'
        r'(?P=i)        pages_info\[name\] = p\.url\n'
        r'(?P=i)    except Exception:\n'
        r'(?P=i)        pages_info\[name\] = "unknown"\n'
        r'(?P=i)active_page = self\.pages\.get\(self\.active_page_name or ""\)\n'
        r'(?P=i)active_bounds = await self\._page_bounds_limited\(active_page\) if active_page else \{\}\n'
    )
    match = pattern.search(text)
    if not match:
        fail("missing anchor browser already running page summaries")
    indent = match.group("i")
    replacement = (
        f"{indent}pages_info = await self.list_pages()\n"
        f"{indent}active_page = await self.resolve_page(None)\n"
        f"{indent}active_bounds = await self._page_bounds_limited(active_page) if active_page else {{}}\n"
    )
    return text[:match.start()] + replacement + text[match.end():]


def replace_browser_already_running_fields(text: str) -> str:
    pattern = re.compile(
        r'(?P<i>[ \t]+)"active_page": self\.active_page_name,\n'
        r'(?P=i)"pages": pages_info,\n'
    )
    match = pattern.search(text)
    if not match:
        fail("missing anchor browser already running result fields")
    indent = match.group("i")
    replacement = (
        f"{indent}\"session_id\": self.session_id,\n"
        f"{indent}\"active_page\": self.active_page_id or self.active_page_name,\n"
        f"{indent}\"active_page_id\": self.active_page_id or self.active_page_name,\n"
        f"{indent}\"page_count\": len(self.pages),\n"
        f"{indent}\"pages\": pages_info,\n"
    )
    return text[:match.start()] + replacement + text[match.end():]


def patch_navigation_capture(path: pathlib.Path, text: str) -> str:
    if "capture_from_start: bool = False" not in text:
        with_page = (
            "async def navigate(\n"
            "    url: str,\n"
            "    page_id: str | None = None,\n"
            "    wait_until: str = \"load\",\n"
        )
        without_page = (
            "async def navigate(\n"
            "    url: str,\n"
            "    wait_until: str = \"load\",\n"
        )
        replacement = (
            "async def navigate(\n"
            "    url: str,\n"
            "    page_id: str | None = None,\n"
            "    capture_from_start: bool = False,\n"
            "    capture_body: bool = False,\n"
            "    capture_url_pattern: str = \"**/*\",\n"
            "    wait_until: str = \"load\",\n"
        )
        if with_page in text:
            text = text.replace(with_page, replacement, 1)
        elif without_page in text:
            text = text.replace(without_page, replacement, 1)
        else:
            fail(f"navigation capture signature anchor missing {path}")
    if "capture_from_start_enabled" not in text:
        text = replace_once(
            text,
            "        warnings: list[str] = []\n        hooks_injected: list[str] = []\n",
            "        warnings: list[str] = []\n        hooks_injected: list[str] = []\n\n"
            "        if capture_from_start:\n"
            "            browser_manager._capturing = True\n"
            "            browser_manager._capture_pattern = capture_url_pattern or \"**/*\"\n"
            "            browser_manager._capture_body = capture_body\n"
            "            warnings.append(\"capture_from_start_enabled\")\n",
            "navigation capture start",
        )
    if "capture_from_start: bool = False" not in text or "capture_from_start_enabled" not in text:
        fail(f"navigation capture validation failed {path}")
    if "_await_no_cancel_wait(page.evaluate(\"document.readyState\")" not in text:
        if "from ..browser import _await_no_cancel_wait" not in text:
            if "from ..browser import _camoufox_debug, _safe_text, _target_domain" in text:
                text = text.replace(
                    "from ..browser import _camoufox_debug, _safe_text, _target_domain",
                    "from ..browser import _await_no_cancel_wait, _camoufox_debug, _safe_text, _target_domain",
                    1,
                )
            elif "from ..browser import _camoufox_debug, _safe_text" in text:
                text = text.replace(
                    "from ..browser import _camoufox_debug, _safe_text",
                    "from ..browser import _await_no_cancel_wait, _camoufox_debug, _safe_text",
                    1,
                )
        text = text.replace(
            "dom_ready = await page.evaluate(\"document.readyState\")",
            "dom_ready = await _await_no_cancel_wait(page.evaluate(\"document.readyState\"), timeout=3.0)",
            1,
        )
    if "aida_clamp_navigation_timeout_ms" not in text:
        if "from ..browser import _await_no_cancel_wait, _camoufox_debug, _safe_text, _target_domain" in text:
            text = text.replace(
                "from ..browser import _await_no_cancel_wait, _camoufox_debug, _safe_text, _target_domain",
                "from ..browser import AIDA_NAVIGATION_DEFAULT_TIMEOUT_MS, aida_clamp_navigation_timeout_ms, _await_no_cancel_wait, _camoufox_debug, _safe_text, _target_domain",
                1,
            )
        elif "from ..browser import _camoufox_debug, _safe_text, _target_domain" in text:
            text = text.replace(
                "from ..browser import _camoufox_debug, _safe_text, _target_domain",
                "from ..browser import AIDA_NAVIGATION_DEFAULT_TIMEOUT_MS, aida_clamp_navigation_timeout_ms, _camoufox_debug, _safe_text, _target_domain",
                1,
            )
    if "nav_timeout_ms" not in text:
        if "    wait_until: str = \"load\",\n    pre_inject_hooks:" in text:
            text = text.replace(
                "    wait_until: str = \"load\",\n    pre_inject_hooks:",
                "    wait_until: str = \"load\",\n    timeout: int = 30000,\n    pre_inject_hooks:",
                1,
            )
        elif "    wait_until: str = \"load\",\n    collect_response_chain:" in text:
            text = text.replace(
                "    wait_until: str = \"load\",\n    collect_response_chain:",
                "    wait_until: str = \"load\",\n    timeout: int = 30000,\n    collect_response_chain:",
                1,
            )
        text = replace_once(
            text,
            "        warnings: list[str] = []\n        hooks_injected: list[str] = []\n",
            "        warnings: list[str] = []\n        hooks_injected: list[str] = []\n"
            "        try:\n"
            "            nav_timeout_ms = aida_clamp_navigation_timeout_ms(timeout)\n"
            "        except Exception:\n"
            "            nav_timeout_ms = AIDA_NAVIGATION_DEFAULT_TIMEOUT_MS\n",
            "navigation timeout budget",
        )
        text = text.replace("timeout=30000)", "timeout=nav_timeout_ms)", 1)
        text = text.replace("await page.wait_for_load_state(state_name, timeout=5000)", "await page.wait_for_load_state(state_name, timeout=max(250, min(5000, nav_timeout_ms)))")
        text = text.replace("resp2 = await page.reload(wait_until=wait_until)", "resp2 = await page.reload(wait_until=wait_until, timeout=nav_timeout_ms)")
    if "nav_timeout_ms" not in text:
        fail(f"navigation timeout validation failed {path}")
    if "_await_no_cancel_wait(page.evaluate(\"document.readyState\")" not in text:
        fail(f"navigation ready-state timeout validation failed {path}")
    if "_navigation_capture_summary" not in text:
        helper = '''_NAVIGATION_CAPTURE_INLINE_LIMIT = 80


def _navigation_request_summary(entry: dict) -> dict:
    response_body = entry.get("response_body")
    response_body_length = int(entry.get("response_body_length") or entry.get("body_length") or (len(response_body) if response_body else 0) or 0)
    request_body = entry.get("request_body") or entry.get("request_post_data") or entry.get("post_data") or ""
    request_body_length = int(entry.get("request_body_length") or len(request_body or "") or 0)
    request_id = entry.get("request_id", entry.get("id"))
    url = str(entry.get("url") or "")
    return {
        "id": entry.get("id"),
        "request_id": request_id,
        "network_request_id": entry.get("network_request_id", request_id),
        "page_id": entry.get("page_id"),
        "context_id": entry.get("context_id"),
        "url": url[:240],
        "url_len": len(url),
        "method": entry.get("method"),
        "status": entry.get("status"),
        "status_code": entry.get("status_code", entry.get("status")),
        "type": entry.get("resource_type"),
        "resource_type": entry.get("resource_type"),
        "ms": entry.get("duration"),
        "duration_ms": entry.get("duration_ms", entry.get("duration")),
        "size": response_body_length,
        "body_length": response_body_length,
        "request_body_length": request_body_length,
        "response_body_length": response_body_length,
        "response_body_available": response_body is not None,
        "failed": bool(entry.get("failed")),
        "failure": entry.get("failure", ""),
        "websocket": bool(entry.get("websocket") or entry.get("resource_type") == "websocket"),
        "redirected_from": entry.get("redirected_from", ""),
        "redirect_chain_count": len(entry.get("redirect_chain") or []) if isinstance(entry.get("redirect_chain"), list) else 0,
    }


def _navigation_capture_summary(page_id: str | None, limit: int = _NAVIGATION_CAPTURE_INLINE_LIMIT) -> dict:
    all_requests = []
    try:
        for entry in list(browser_manager._network_requests):
            if page_id and entry.get("page_id") not in {page_id, None}:
                continue
            all_requests.append(entry)
    except Exception as exc:
        return {
            "status": "capture_summary_failed",
            "error": _safe_text(exc, 500),
            "requests": [],
            "count": 0,
            "returned_count": 0,
            "total_count": 0,
            "truncated": False,
            "capture_compacted": True,
        }
    safe_limit = max(0, int(limit or 0))
    summaries = [_navigation_request_summary(entry) for entry in all_requests[:safe_limit]]
    return {
        "status": "captured" if summaries else "empty",
        "requests": summaries,
        "count": len(summaries),
        "returned_count": len(summaries),
        "total_count": len(all_requests),
        "truncated": len(all_requests) > len(summaries),
        "limit": safe_limit,
        "page_id": page_id,
        "active": browser_manager._capturing,
        "capture_compacted": True,
        "body_access": "browser_network.get_request",
    }


'''
        text = replace_once(
            text,
            "\n\n@mcp.tool()\nasync def navigate(",
            "\n\n" + helper + "@mcp.tool()\nasync def navigate(",
            "navigation capture summary helpers",
        )
    if "captured_requests.append(dict(entry))" in text:
        old_block = '''        captured_requests = []
        try:
            for entry in list(browser_manager._network_requests):
                if resolved_page_id and entry.get("page_id") not in {resolved_page_id, None}:
                    continue
                captured_requests.append(dict(entry))
                if len(captured_requests) >= 300:
                    break
        except Exception:
            captured_requests = []
        if captured_requests:
            out["network_requests"] = captured_requests
            out["network_capture"] = {
                "status": "captured",
                "requests": captured_requests,
                "count": len(captured_requests),
                "page_id": resolved_page_id,
                "active": browser_manager._capturing,
            }
'''
        new_block = '''        capture_summary = _navigation_capture_summary(resolved_page_id)
        if capture_summary.get("returned_count", 0) > 0:
            out["network_requests"] = capture_summary["requests"]
            out["network_capture"] = capture_summary
'''
        text = replace_once(text, old_block, new_block, "navigation compact capture response")
    if "_navigation_capture_summary" not in text or "capture_compacted" not in text or "body_access" not in text:
        fail(f"navigation compact capture validation failed {path}")
    return text


def patch_navigation_launch_params(path: pathlib.Path, text: str) -> str:
    if "AIDA_LAUNCH_DEFAULT_BUNDLED_VISIBLE_MS" not in text and "from ..browser import " in text:
        text = text.replace(
            "from ..browser import ",
            "from ..browser import AIDA_LAUNCH_DEFAULT_BUNDLED_VISIBLE_MS, ",
            1,
        )
    if "profile_dir: str | None = None" not in text:
        text = replace_once(
            text,
            "    launch_timeout_ms: int = 30000,\n) -> dict:\n",
            "    launch_timeout_ms: int = AIDA_LAUNCH_DEFAULT_BUNDLED_VISIBLE_MS,\n"
            "    persistent_context: bool = False,\n"
            "    profile_dir: str | None = None,\n"
            "    user_data_dir: str | None = None,\n"
            "    bridge_generation: int | str | None = None,\n"
            "    bridge_session_id: str | None = None,\n"
            "    bridge_attempt_id: str | None = None,\n"
            ") -> dict:\n",
            f"navigation launch persistent signature {path}",
        )
    elif "bridge_generation: int | str | None = None" not in text:
        if "    privacy_fail_closed: bool = True,\n" in text:
            text = replace_once(
                text,
                "    privacy_fail_closed: bool = True,\n",
                "    privacy_fail_closed: bool = True,\n"
                "    bridge_generation: int | str | None = None,\n"
                "    bridge_session_id: str | None = None,\n"
                "    bridge_attempt_id: str | None = None,\n",
                f"navigation launch bridge diagnostics signature {path}",
            )
        else:
            text = replace_once(
                text,
                "    user_data_dir: str | None = None,\n"
                ") -> dict:\n",
                "    user_data_dir: str | None = None,\n"
                "    bridge_generation: int | str | None = None,\n"
                "    bridge_session_id: str | None = None,\n"
                "    bridge_attempt_id: str | None = None,\n"
                ") -> dict:\n",
                f"navigation launch bridge diagnostics signature {path}",
            )
    if "service_workers: str | None = None" not in text:
        if "    privacy_fail_closed: bool = True,\n" in text:
            text = replace_once(
                text,
                "    privacy_fail_closed: bool = True,\n",
                "    privacy_fail_closed: bool = True,\n"
                "    service_workers: str | None = None,\n"
                "    block_service_workers: bool = False,\n"
                "    aida_fast_visible_launch: bool | None = None,\n"
                "    aida_launch_policy_marker: str | None = None,\n",
                f"navigation launch policy signature {path}",
            )
        elif "    bridge_attempt_id: str | None = None,\n" in text:
            text = replace_once(
                text,
                "    bridge_attempt_id: str | None = None,\n",
                "    bridge_attempt_id: str | None = None,\n"
                "    service_workers: str | None = None,\n"
                "    block_service_workers: bool = False,\n"
                "    aida_fast_visible_launch: bool | None = None,\n"
                "    aida_launch_policy_marker: str | None = None,\n",
                f"navigation launch policy signature {path}",
            )
        else:
            text = replace_once(
                text,
                "    user_data_dir: str | None = None,\n"
                ") -> dict:\n",
                "    user_data_dir: str | None = None,\n"
                "    service_workers: str | None = None,\n"
                "    block_service_workers: bool = False,\n"
                "    aida_fast_visible_launch: bool | None = None,\n"
                "    aida_launch_policy_marker: str | None = None,\n"
                ") -> dict:\n",
                f"navigation launch policy signature {path}",
            )
    if "config[\"persistent_context\"] = True" not in text:
        text = replace_once(
            text,
            "        if ff_version is not None:\n"
            "            try:\n"
            "                config[\"ff_version\"] = int(ff_version)\n"
            "            except (TypeError, ValueError):\n"
            "                pass\n"
            "        if proxy:\n",
            "        if ff_version is not None:\n"
            "            try:\n"
            "                config[\"ff_version\"] = int(ff_version)\n"
            "            except (TypeError, ValueError):\n"
            "                pass\n"
            "        if persistent_context or profile_dir or user_data_dir:\n"
            "            config[\"persistent_context\"] = True\n"
            "        if profile_dir:\n"
            "            config[\"profile_dir\"] = profile_dir\n"
            "        if user_data_dir:\n"
            "            config[\"user_data_dir\"] = user_data_dir\n"
            "        if proxy:\n",
            f"navigation launch persistent config {path}",
        )
    if "config[\"bridge_generation\"] = bridge_generation" not in text:
        text = replace_once(
            text,
            "        if profile_dir:\n"
            "            config[\"profile_dir\"] = profile_dir\n"
            "        if user_data_dir:\n"
            "            config[\"user_data_dir\"] = user_data_dir\n"
            "        if proxy:\n",
            "        if profile_dir:\n"
            "            config[\"profile_dir\"] = profile_dir\n"
            "        if user_data_dir:\n"
            "            config[\"user_data_dir\"] = user_data_dir\n"
            "        if bridge_generation is not None:\n"
            "            config[\"bridge_generation\"] = bridge_generation\n"
            "        if bridge_session_id:\n"
            "            config[\"bridge_session_id\"] = bridge_session_id\n"
            "        if bridge_attempt_id:\n"
            "            config[\"bridge_attempt_id\"] = bridge_attempt_id\n"
            "        if proxy:\n",
            f"navigation launch bridge diagnostics config {path}",
        )
    if "config[\"service_workers\"] = str(service_workers)" not in text:
        text = replace_once(
            text,
            "        if user_data_dir:\n"
            "            config[\"user_data_dir\"] = user_data_dir\n",
            "        if user_data_dir:\n"
            "            config[\"user_data_dir\"] = user_data_dir\n"
            "        if service_workers is not None:\n"
            "            config[\"service_workers\"] = str(service_workers)\n"
            "        if block_service_workers:\n"
            "            config[\"block_service_workers\"] = True\n"
            "        if aida_fast_visible_launch is not None:\n"
            "            config[\"aida_fast_visible_launch\"] = bool(aida_fast_visible_launch)\n"
            "        if aida_launch_policy_marker:\n"
            "            config[\"aida_launch_policy_marker\"] = str(aida_launch_policy_marker)\n",
            f"navigation launch policy config {path}",
        )
    if ("profile_dir: str | None = None" not in text or
            "config[\"persistent_context\"] = True" not in text or
            "bridge_generation: int | str | None = None" not in text or
            "service_workers: str | None = None" not in text or
            "aida_fast_visible_launch: bool | None = None" not in text or
            "config[\"service_workers\"] = str(service_workers)" not in text or
            "config[\"aida_fast_visible_launch\"] = bool(aida_fast_visible_launch)" not in text):
        fail(f"navigation launch persistent validation failed {path}")
    return text


def patch_browser_launch_deadline_diagnostics(text: str) -> str:
    if "launch_phase_deadline" not in text and "_budget_remaining_ms" in text and "_launch_debug_snapshot" in text and "launch_error_cleanup_counts" in text:
        return text
    if "launch_phase_deadline" not in text:
        text = replace_once(
            text,
            "        launch_timeout_floor_ms = 5000 if fast_probe else (32000 if bundled_visible_launch else 5000)\n"
            "        launch_timeout_ms = min(max(_int_config(cfg.get(\"launch_timeout_ms\"), 30000), launch_timeout_floor_ms), 120000)\n",
            "        launch_budget_policy = aida_resolve_launch_budget_policy(cfg.get(\"launch_timeout_ms\"), bundled_visible_launch=bundled_visible_launch, fast_probe=fast_probe)\n"
            "        launch_timeout_ms = int(launch_budget_policy[\"launch_timeout_ms\"])\n"
            "        launch_deadline = time.perf_counter() + (launch_timeout_ms / 1000.0)\n"
            "        launch_generation = str(cfg.get(\"bridge_generation\") or cfg.get(\"generation\") or \"\")\n"
            "        launch_session_id = str(cfg.get(\"bridge_session_id\") or cfg.get(\"session_id\") or self.session_id or \"default\")\n"
            "        launch_attempt_id = str(cfg.get(\"bridge_attempt_id\") or \"\")\n"
            "        phase_timings: dict[str, dict[str, Any]] = {}\n"
            "        launch_phase = \"launch_phase_deadline\"\n"
            "        selected_page_id = \"\"\n"
            "        selected_page_url = \"\"\n"
            "        selected_page_title = \"\"\n"
            "        page_event_count = 0\n"
            "        privacy_info: dict[str, Any] = {}\n\n"
            "        def _launch_remaining_ms() -> int:\n"
            "            return max(0, int((launch_deadline - time.perf_counter()) * 1000))\n\n"
            "        def _launch_process_snapshot() -> dict[str, Any]:\n"
            "            try:\n"
            "                descendants = _windows_descendant_pids(_os.getpid())\n"
            "            except Exception as exc:\n"
            "                return {\"pid\": _os.getpid(), \"ppid\": _os.getppid() if hasattr(_os, \"getppid\") else 0, \"descendant_error\": _safe_text(exc, 240)}\n"
            "            return {\"pid\": _os.getpid(), \"ppid\": _os.getppid() if hasattr(_os, \"getppid\") else 0, \"descendant_count\": len(descendants), \"descendants\": descendants[:32]}\n\n"
            "        async def _launch_wait_phase(name: str, awaitable, cap_s: float | None = None):\n"
            "            nonlocal launch_phase\n"
            "            launch_phase = name\n"
            "            phase_started = time.perf_counter()\n"
            "            remaining_ms = _launch_remaining_ms()\n"
            "            timeout_s = remaining_ms / 1000.0\n"
            "            if cap_s is not None and cap_s > 0:\n"
            "                timeout_s = min(timeout_s, cap_s)\n"
            "            phase_timings[name] = {\"remaining_ms\": remaining_ms, \"timeout_ms\": int(timeout_s * 1000), \"started_ms\": int((phase_started - launch_started) * 1000)}\n"
            "            _camoufox_debug(\"launch_phase_begin\", session_id=launch_session_id, generation=launch_generation, attempt_id=launch_attempt_id, phase=name, elapsed_ms=int((phase_started - launch_started) * 1000), remaining_ms=remaining_ms, timeout_ms=int(timeout_s * 1000), process=_launch_process_snapshot())\n"
            "            if remaining_ms <= 0 or timeout_s <= 0:\n"
            "                close = getattr(awaitable, \"close\", None)\n"
            "                if callable(close):\n"
            "                    close()\n"
            "                phase_timings[name][\"status\"] = \"timeout_before_start\"\n"
            "                _camoufox_debug(\"launch_phase_timeout\", session_id=launch_session_id, generation=launch_generation, attempt_id=launch_attempt_id, phase=name, elapsed_ms=int((time.perf_counter() - launch_started) * 1000), remaining_ms=0, timeout_ms=0, status=\"timeout_before_start\", process=_launch_process_snapshot())\n"
            "                raise asyncio.TimeoutError(f\"launch phase {name} had no remaining budget\")\n"
            "            try:\n"
            "                result = await asyncio.wait_for(awaitable, timeout=max(0.001, timeout_s))\n"
            "                elapsed_phase_ms = int((time.perf_counter() - phase_started) * 1000)\n"
            "                phase_timings[name][\"status\"] = \"ok\"\n"
            "                phase_timings[name][\"elapsed_ms\"] = elapsed_phase_ms\n"
            "                phase_timings[name][\"remaining_after_ms\"] = _launch_remaining_ms()\n"
            "                _camoufox_debug(\"launch_phase_ok\", session_id=launch_session_id, generation=launch_generation, attempt_id=launch_attempt_id, phase=name, elapsed_ms=int((time.perf_counter() - launch_started) * 1000), phase_elapsed_ms=elapsed_phase_ms, remaining_ms=_launch_remaining_ms(), process=_launch_process_snapshot())\n"
            "                return result\n"
            "            except asyncio.TimeoutError:\n"
            "                elapsed_phase_ms = int((time.perf_counter() - phase_started) * 1000)\n"
            "                phase_timings[name][\"status\"] = \"timeout\"\n"
            "                phase_timings[name][\"elapsed_ms\"] = elapsed_phase_ms\n"
            "                phase_timings[name][\"remaining_after_ms\"] = _launch_remaining_ms()\n"
            "                _camoufox_debug(\"launch_phase_timeout\", session_id=launch_session_id, generation=launch_generation, attempt_id=launch_attempt_id, phase=name, elapsed_ms=int((time.perf_counter() - launch_started) * 1000), phase_elapsed_ms=elapsed_phase_ms, remaining_ms=_launch_remaining_ms(), timeout_ms=int(timeout_s * 1000), process=_launch_process_snapshot())\n"
            "                raise\n"
            "            except Exception as exc:\n"
            "                elapsed_phase_ms = int((time.perf_counter() - phase_started) * 1000)\n"
            "                phase_timings[name][\"status\"] = \"exception\"\n"
            "                phase_timings[name][\"elapsed_ms\"] = elapsed_phase_ms\n"
            "                phase_timings[name][\"remaining_after_ms\"] = _launch_remaining_ms()\n"
            "                phase_timings[name][\"error_type\"] = type(exc).__name__\n"
            "                phase_timings[name][\"error_repr\"] = _safe_text(repr(exc), 700)\n"
            "                _camoufox_debug(\"launch_phase_exception\", session_id=launch_session_id, generation=launch_generation, attempt_id=launch_attempt_id, phase=name, elapsed_ms=int((time.perf_counter() - launch_started) * 1000), phase_elapsed_ms=elapsed_phase_ms, remaining_ms=_launch_remaining_ms(), error_type=type(exc).__name__, error_summary=_safe_text(exc), error_repr=_safe_text(repr(exc), 700), process=_launch_process_snapshot())\n"
            "                raise\n",
            "browser launch deadline helpers",
        )
    if "generation=launch_generation" not in text:
        text = replace_once(
            text,
            "            timeout_ms=launch_timeout_ms,\n"
            "            fast_probe=fast_probe,\n",
            "            timeout_ms=launch_timeout_ms,\n"
            "            remaining_ms=_launch_remaining_ms(),\n"
            "            session_id=launch_session_id,\n"
            "            generation=launch_generation,\n"
            "            attempt_id=launch_attempt_id,\n"
            "            process=_launch_process_snapshot(),\n"
            "            fast_probe=fast_probe,\n",
            "browser launch start deadline fields",
        )
    text = text.replace(
        "self.browser = await asyncio.wait_for(self._cm.__aenter__(), timeout=launch_timeout_ms / 1000)",
        "self.browser = await _launch_wait_phase(\"context_enter\", self._cm.__aenter__())",
    )
    text = text.replace(
        "ctx = await asyncio.wait_for(self.browser.new_context(), timeout=max(5.0, launch_timeout_ms / 3000))",
        "ctx, _, _ = await _create_camoufox_safe_context(self.browser, {}, max(5.0, launch_timeout_ms / 3000), \"launch_new_context\", None, launch_started)",
    )
    text = text.replace(
        "ctx = await asyncio.wait_for(self.browser.new_context(), timeout=min(max(8.0, max(5.0, launch_timeout_ms / 1000.0) * 0.50), max(5.0, launch_timeout_ms / 1000.0)))",
        "ctx, _, _ = await _create_camoufox_safe_context(self.browser, {}, min(max(8.0, max(5.0, launch_timeout_ms / 1000.0) * 0.50), max(5.0, launch_timeout_ms / 1000.0)), \"launch_new_context\", None, launch_started)",
    )
    text = text.replace(
        "await ctx.add_init_script(get_font_fallback_script())",
        "await _launch_wait_phase(\"font_fallback_script\", ctx.add_init_script(get_font_fallback_script()), 5.0)",
    )
    text = text.replace(
        "await ctx.add_init_script(script=script_info[\"content\"])",
        "await _launch_wait_phase(\"persistent_script\", ctx.add_init_script(script=script_info[\"content\"]), 5.0)",
    )
    text = text.replace(
        "candidate = await _await_no_cancel_wait(ctx.wait_for_event(\"page\"), timeout=page_wait_timeout_s)",
        "candidate = await _launch_wait_phase(\"page_event\", ctx.wait_for_event(\"page\"), page_wait_timeout_s)\n"
        "                    page_event_count += 1",
    )
    text = text.replace(
        "page = await _await_no_cancel_wait(ctx.new_page(), timeout=page_create_timeout_s)",
        "page = await _launch_wait_phase(\"new_page\", ctx.new_page(), page_create_timeout_s)",
    )
    text = text.replace(
        "page = await asyncio.wait_for(ctx.new_page(), timeout=max(5.0, launch_timeout_ms / 3000))",
        "page = await _launch_wait_phase(\"new_page\", ctx.new_page(), max(5.0, launch_timeout_ms / 3000))",
    )
    text = text.replace(
        "page = await asyncio.wait_for(ctx.new_page(), timeout=min(max(15.0, max(5.0, launch_timeout_ms / 1000.0) * 0.75), max(5.0, launch_timeout_ms / 1000.0)))",
        "page = await _launch_wait_phase(\"new_page\", ctx.new_page(), min(max(15.0, max(5.0, launch_timeout_ms / 1000.0) * 0.75), max(5.0, launch_timeout_ms / 1000.0)))",
    )
    text = text.replace(
        "await _await_no_cancel_wait(extra.close(), timeout=5.0)",
        "await _launch_wait_phase(\"duplicate_page_close\", extra.close(), 5.0)",
    )
    launch_privacy_anchor = (
        "            privacy_info = await _verify_page_privacy(page, self._context_plan)\n"
        "            _camoufox_debug(\"launch_privacy_verified\", **privacy_info)\n"
    )
    if launch_privacy_anchor in text:
        text = text.replace(
            launch_privacy_anchor,
            "            privacy_info = await _launch_wait_phase(\"privacy_probe\", _verify_page_privacy(page, getattr(self, \"_context_plan\", {\"ua_policy\": \"camoufox_native\", \"block_webrtc\": True, \"privacy_fail_closed\": True, \"fingerprint_overrides\": {}})), min(12.0, max(1.0, _launch_remaining_ms() / 1000.0)))\n"
            "            _camoufox_debug(\"launch_privacy_verified\", **privacy_info)\n",
            1,
        )
    elif "launch_privacy_verified" in text and "privacy_probe" not in text:
        fail("browser launch privacy anchor missing")
    text = text.replace(
        "        privacy_info = await _verify_page_privacy(page, self._context_plan)\n",
        "        privacy_info = await _verify_page_privacy(page, getattr(self, \"_context_plan\", {\"ua_policy\": \"camoufox_native\", \"block_webrtc\": True, \"privacy_fail_closed\": True, \"fingerprint_overrides\": {}}))\n",
    )
    if "selected_page_title = await _launch_wait_phase(\"title_probe\"" not in text:
        text = replace_once(
            text,
            "            page_bounds = await self._page_bounds_limited(page)\n"
            "            elapsed_ms = int((time.perf_counter() - launch_started) * 1000)\n",
            "            page_bounds = await _launch_wait_phase(\"page_bounds\", self._page_bounds_limited(page), 3.0)\n"
            "            try:\n"
            "                page_id_fn = getattr(self, \"page_id_for\", None)\n"
            "                selected_page_id = str(page_id_fn(page) if callable(page_id_fn) else (self.active_page_name or \"default\") or \"default\")\n"
            "            except Exception as exc:\n"
            "                selected_page_id = self.active_page_name or \"default\"\n"
            "                phase_timings[\"page_id_probe\"] = {\"status\": \"exception\", \"error_type\": type(exc).__name__, \"error_repr\": _safe_text(repr(exc), 700)}\n"
            "            try:\n"
            "                selected_page_url = str(page.url or \"\")\n"
            "            except Exception as exc:\n"
            "                phase_timings[\"url_probe\"] = {\"status\": \"exception\", \"error_type\": type(exc).__name__, \"error_repr\": _safe_text(repr(exc), 700)}\n"
            "            try:\n"
            "                selected_page_title = await _launch_wait_phase(\"title_probe\", page.title(), 3.0)\n"
            "            except asyncio.TimeoutError:\n"
            "                raise\n"
            "            except Exception as exc:\n"
            "                selected_page_title = \"\"\n"
            "                phase_timings[\"title_probe\"] = {\"status\": \"exception\", \"error_type\": type(exc).__name__, \"error_repr\": _safe_text(repr(exc), 700), \"remaining_after_ms\": _launch_remaining_ms()}\n"
            "            elapsed_ms = int((time.perf_counter() - launch_started) * 1000)\n",
            "browser launch page probes",
        )
    if "\"phase_timings\": phase_timings" not in text:
        text = replace_once(
            text,
            "                \"pages\": len(self.pages),\n"
            "                \"active_page_id\": self.active_page_id,\n"
            "                \"profile\": profile_info,\n",
            "                \"pages\": len(self.pages),\n"
            "                \"active_page_id\": self.active_page_id,\n"
            "                \"phase\": launch_phase,\n"
            "                \"phase_timings\": phase_timings,\n"
            "                \"remaining_ms\": _launch_remaining_ms(),\n"
            "                \"session_id\": launch_session_id,\n"
            "                \"generation\": launch_generation,\n"
            "                \"attempt_id\": launch_attempt_id,\n"
            "                \"process\": _launch_process_snapshot(),\n"
            "                \"selected_page\": {\"page_id\": selected_page_id, \"url_len\": len(selected_page_url), \"title_len\": len(selected_page_title), \"event_count\": page_event_count},\n"
            "                \"privacy\": privacy_info,\n"
            "                \"profile\": profile_info,\n",
            "browser launch diagnostics phase payload",
        )
    if "selected_page_id=selected_page_id" not in text:
        text = replace_once(
            text,
            "                page_bounds=page_bounds,\n"
            "                profile=profile_info,\n",
            "                page_bounds=page_bounds,\n"
            "                session_id=launch_session_id,\n"
            "                generation=launch_generation,\n"
            "                attempt_id=launch_attempt_id,\n"
            "                remaining_ms=_launch_remaining_ms(),\n"
            "                phase=launch_phase,\n"
            "                phase_timings=phase_timings,\n"
            "                process=_launch_process_snapshot(),\n"
            "                selected_page_id=selected_page_id,\n"
            "                selected_url_len=len(selected_page_url),\n"
            "                selected_title_len=len(selected_page_title),\n"
            "                page_event_count=page_event_count,\n"
            "                privacy=privacy_info,\n"
            "                profile=profile_info,\n",
            "browser launch ready deadline fields",
        )
    if "error_repr=_safe_text(repr(exc), 1000)" not in text:
        text = replace_once(
            text,
            "                error_summary=_safe_text(exc),\n"
            "                window=window_diag,\n",
            "                error_summary=_safe_text(exc),\n"
            "                error_repr=_safe_text(repr(exc), 1000),\n"
            "                status=\"timeout\" if isinstance(exc, asyncio.TimeoutError) else \"error\",\n"
            "                phase=launch_phase,\n"
            "                phase_timings=phase_timings,\n"
            "                remaining_ms=_launch_remaining_ms(),\n"
            "                session_id=launch_session_id,\n"
            "                generation=launch_generation,\n"
            "                attempt_id=launch_attempt_id,\n"
            "                process=_launch_process_snapshot(),\n"
            "                privacy=privacy_info,\n"
            "                window=window_diag,\n",
            "browser launch exception deadline fields",
        )
    if "return {\"error\": _safe_text(exc, 1000), \"status\": \"timeout\" if isinstance(exc, asyncio.TimeoutError) else \"error\"" not in text:
        text = replace_once(
            text,
            "            raise\n\n    async def _ensure_browser",
            "            return {\"error\": _safe_text(exc, 1000), \"status\": \"timeout\" if isinstance(exc, asyncio.TimeoutError) else \"error\", \"phase\": launch_phase, \"timeout_phase\": launch_phase if isinstance(exc, asyncio.TimeoutError) else None, \"exception_type\": type(exc).__name__, \"exception_repr\": _safe_text(repr(exc), 1000), \"elapsed_ms\": elapsed_ms, \"remaining_ms\": _launch_remaining_ms(), \"session_id\": launch_session_id, \"generation\": launch_generation, \"attempt_id\": launch_attempt_id, \"diagnostics\": {\"phase\": launch_phase, \"phase_timings\": phase_timings, \"remaining_ms\": _launch_remaining_ms(), \"session_id\": launch_session_id, \"generation\": launch_generation, \"attempt_id\": launch_attempt_id, \"process\": _launch_process_snapshot(), \"selected_page\": {\"page_id\": selected_page_id, \"url_len\": len(selected_page_url), \"title_len\": len(selected_page_title), \"event_count\": page_event_count}, \"privacy\": privacy_info, \"profile\": profile_info, \"window\": window_diag}}\n\n    async def _ensure_browser",
            "browser launch structured exception return",
        )
    for marker in ("launch_phase_deadline", "_launch_remaining_ms", "launch_phase_begin", "phase_timings", "timeout_phase", "privacy_probe"):
        if marker not in text:
            fail(f"browser launch deadline validation missing {marker}")
    return text


def patch_browser_camoufox_stability(text: str) -> str:
    if "AIDA_CAMOUFOX_BRIDGE_PATCH_ID" not in text:
        text = replace_once(
            text,
            'PRIVACY_VERIFY_URL = "data:text/html,%3C!doctype%20html%3E%3Ctitle%3EAiDA%20Camoufox%3C/title%3E"\n',
            'PRIVACY_VERIFY_URL = "data:text/html,%3C!doctype%20html%3E%3Ctitle%3EAiDA%20Camoufox%3C/title%3E"\n'
            'AIDA_CAMOUFOX_BRIDGE_PATCH_ID = "aida_camoufox_bridge_20260620_crash_diag_1"\n',
            "browser bridge patch id",
        )
    if "AIDA_FAST_VISIBLE_POLICY_MARKER" not in text:
        text = replace_once(
            text,
            'AIDA_CAMOUFOX_BRIDGE_PATCH_ID = "aida_camoufox_bridge_20260620_crash_diag_1"\n',
            'AIDA_CAMOUFOX_BRIDGE_PATCH_ID = "aida_camoufox_bridge_20260620_crash_diag_1"\n'
            f'AIDA_FAST_VISIBLE_POLICY_MARKER = "{AIDA_FAST_VISIBLE_POLICY_V1}"\n',
            "browser fast-visible policy marker",
        )
    if "def _flag_enabled(value: Any) -> bool:" not in text:
        helper = '''def _flag_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enable", "enabled"}


def _target_closed_error(exc: Exception) -> bool:
    name = type(exc).__name__
    text = str(exc)
    return "TargetClosed" in name or "target closed" in text.lower() or "has been closed" in text.lower()


'''
        text, count = re.subn(
            r"(def _int_config\(value: Any, fallback: int\) -> int:\n(?:    .+\n)+?    return parsed if parsed > 0 else fallback\n\n)",
            r"\1" + helper,
            text,
            count=1,
        )
        if count != 1:
            fail("browser stability helper anchor missing")
    text = text.replace(
        '    context_options: dict[str, Any] = {"service_workers": "block"}\n',
        '    context_options: dict[str, Any] = {}\n'
        '    service_worker_policy = str(cfg.get("service_workers") or "").strip().lower()\n'
        '    if _flag_enabled(cfg.get("block_service_workers")) or service_worker_policy in {"block", "blocked", "disable", "disabled"}:\n'
        '        context_options["service_workers"] = "block"\n'
        '    elif service_worker_policy in {"allow", "allowed", "enable", "enabled"}:\n'
        '        context_options["service_workers"] = "allow"\n',
    )
    text = re.sub(
        r"def _fast_visible_privacy_plan\(plan: dict\[str, Any\]\) -> dict\[str, Any\]:\n(?:    .+\n)+?\n\ndef _fast_visible_firefox_user_prefs",
        "def _fast_visible_privacy_plan(plan: dict[str, Any]) -> dict[str, Any]:\n"
        "    return dict(plan)\n\n\n"
        "def _fast_visible_firefox_user_prefs",
        text,
        count=1,
    )
    text = text.replace('    opts["service_workers"] = "block"\n', "")
    text, fast_visible_policy_count = re.subn(
        r"def _use_fast_visible_launch\(cfg: dict\[str, Any\], bundled_visible_launch: bool, profile_requested: bool\) -> bool:\n(?:    .+\n)+?\n\n",
        "def _use_fast_visible_launch(cfg: dict[str, Any], bundled_visible_launch: bool, profile_requested: bool) -> bool:\n"
        "    return False\n\n",
        text,
        count=1,
    )
    if fast_visible_policy_count != 1:
        fail("browser fast-visible launch policy anchor missing")
    if "aida_bridge_patch_active" not in text:
        text = replace_once(
            text,
            "        cfg = {**self.default_config, **(config or {})}\n",
            "        cfg = {**self.default_config, **(config or {})}\n"
            "        _camoufox_debug(\n"
            "            \"aida_bridge_patch_active\",\n"
            "            patch_version=AIDA_CAMOUFOX_BRIDGE_PATCH_ID,\n"
            "            default_launch_path=\"async_camoufox\",\n"
            "            fast_visible_default=False,\n"
            "            service_workers_default=\"allow\",\n"
            "            ua_policy_default=\"camoufox_native\",\n"
            "            request_marker=_safe_text(cfg.get(\"aida_launch_policy_marker\")),\n"
            "            config_keys=sorted(str(k) for k in cfg.keys()),\n"
            "        )\n",
            "browser bridge patch active log",
        )
    text = text.replace(
        '            patch_version="aida_camoufox_bridge_20260619_1",\n',
        '            patch_version=AIDA_CAMOUFOX_BRIDGE_PATCH_ID,\n',
    )
    fast_visible_compat_path_marker = "fast_visible_" + "firefox_" + "compat"
    legacy_launch_path_line = (
        '            selected_launch_path="' +
        fast_visible_compat_path_marker +
        '" if ' +
        'fast_visible_launch else "async_camoufox",\n'
    )
    text = text.replace(
        legacy_launch_path_line,
        '            selected_launch_path="async_camoufox",\n',
    )
    if "aida_launch_policy_resolved" not in text:
        text = replace_once(
            text,
            "        fast_visible_launch = _use_fast_visible_launch(cfg, bundled_visible_launch, profile_requested)\n",
            "        fast_visible_launch = _use_fast_visible_launch(cfg, bundled_visible_launch, profile_requested)\n"
            "        fast_visible_requested = _flag_enabled(cfg.get(\"aida_fast_visible_launch\"))\n"
            "        fast_visible_env_requested = _flag_enabled(_os.environ.get(\"AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK\"))\n"
            "        if fast_visible_launch or fast_visible_requested or fast_visible_env_requested:\n"
            "            _camoufox_debug(\n"
            "                \"aida_fast_visible_fallback_ignored\",\n"
            "                patch_version=AIDA_CAMOUFOX_BRIDGE_PATCH_ID,\n"
            "                requested=bool(fast_visible_requested),\n"
            "                env=bool(fast_visible_env_requested),\n"
            "                forced_launch_path=\"async_camoufox\",\n"
            "            )\n"
            "        fast_visible_launch = False\n"
            "        fast_visible_source = \"default\"\n"
            "        if cfg.get(\"aida_fast_visible_launch\") is not None:\n"
            "            fast_visible_source = \"request\"\n"
            "        elif _os.environ.get(\"AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK\") is not None:\n"
            "            fast_visible_source = \"env\"\n"
            "        _camoufox_debug(\n"
            "            \"aida_launch_policy_resolved\",\n"
            "            patch_version=AIDA_CAMOUFOX_BRIDGE_PATCH_ID,\n"
            "            selected_launch_path=\"async_camoufox\",\n"
            "            fast_visible_source=fast_visible_source,\n"
            "            bundled_visible=bool(bundled_visible_launch),\n"
            "            profile_requested=bool(profile_requested),\n"
            "            fast_visible_enabled=bool(fast_visible_launch),\n"
            "            fast_visible_requested=_safe_text(cfg.get(\"aida_fast_visible_launch\")),\n"
            "            fast_visible_env=bool(_os.environ.get(\"AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK\")),\n"
            "            block_service_workers=bool(_flag_enabled(cfg.get(\"block_service_workers\"))),\n"
            "            service_workers=_safe_text(cfg.get(\"service_workers\")),\n"
            "            service_workers_default=\"allow\",\n"
            "            context_service_workers=context_plan.get(\"context_options\", {}).get(\"service_workers\", \"\"),\n"
            "            ua_policy=context_plan.get(\"ua_policy\"),\n"
            "            ua_override=bool(context_plan.get(\"user_agent\")),\n"
            "            request_marker=_safe_text(cfg.get(\"aida_launch_policy_marker\")),\n"
            "        )\n",
            "browser launch policy resolved log",
        )
    elif "aida_fast_visible_fallback_ignored" not in text:
        text = replace_once(
            text,
            "        fast_visible_launch = _use_fast_visible_launch(cfg, bundled_visible_launch, profile_requested)\n",
            "        fast_visible_launch = _use_fast_visible_launch(cfg, bundled_visible_launch, profile_requested)\n"
            "        fast_visible_requested = _flag_enabled(cfg.get(\"aida_fast_visible_launch\"))\n"
            "        fast_visible_env_requested = _flag_enabled(_os.environ.get(\"AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK\"))\n"
            "        if fast_visible_launch or fast_visible_requested or fast_visible_env_requested:\n"
            "            _camoufox_debug(\n"
            "                \"aida_fast_visible_fallback_ignored\",\n"
            "                patch_version=AIDA_CAMOUFOX_BRIDGE_PATCH_ID,\n"
            "                requested=bool(fast_visible_requested),\n"
            "                env=bool(fast_visible_env_requested),\n"
            "                forced_launch_path=\"async_camoufox\",\n"
            "            )\n"
            "        fast_visible_launch = False\n",
            "browser ignored fast-visible fallback log",
        )
    text = text.replace("launch_" + "fast_visible" + "_compat_selected", "aida_fast_visible_fallback_ignored_after_plan")
    text = re.sub(
        r'        if fast_visible_launch:\n(?:            .+\n)+?        if context_plan\.get\("user_agent"\):\n',
        '        if fast_visible_launch:\n'
        '            fast_visible_launch = False\n'
        '        if context_plan.get("user_agent"):\n',
        text,
        count=1,
    )
    text = text.replace(
        '                ctx = await self.browser.new_context(service_workers="block")\n',
        '                ctx, _, _ = await _create_camoufox_safe_context(self.browser, {"service_workers": "block"}, 30.0, "storage_import_context")\n',
    )
    if '"browser_ready_ms": elapsed_ms' not in text:
        text = replace_once(
            text,
            '                "privacy": privacy_info,\n'
            '                "context_source": context_source,\n'
            '            }\n',
            '                "privacy": privacy_info,\n'
            '                "context_source": context_source,\n'
            '                "browser_ready_ms": elapsed_ms,\n'
            '                "camoufox_launch_ms": elapsed_ms,\n'
            '            }\n',
            "browser normal launch timing diagnostics",
        )
        text = replace_once(
            text,
            '                "window_height": window_size[1],\n'
            '                "diagnostics": diagnostics,\n'
            '            }\n',
            '                "window_height": window_size[1],\n'
            '                "diagnostics": diagnostics,\n'
            '                "browser_ready_ms": elapsed_ms,\n'
            '                "camoufox_launch_ms": elapsed_ms,\n'
            '            }\n',
            "browser normal launch timing response",
        )
    if "def _handle_context_close_event" not in text:
        text = text.replace(
            "        listener_registered = False\n",
            "        page_listener_registered = False\n"
            "        close_listener_registered = False\n",
            1,
        )
        text = text.replace(
            "            listener_registered = True\n",
            "            page_listener_registered = True\n",
            1,
        )
        text = text.replace(
            "        except Exception as exc:\n"
            "            _camoufox_debug(\"context_listener_failed\", session_id=self.session_id, context_id=context_id, error_type=type(exc).__name__, error=_safe_text(exc, 300))\n",
            "        except Exception as exc:\n"
            "            _camoufox_debug(\"context_listener_failed\", session_id=self.session_id, context_id=context_id, error_type=type(exc).__name__, error=_safe_text(exc, 300))\n"
            "        try:\n"
            "            ctx.on(\"close\", lambda *_, cid=context_id, c=ctx: self._handle_context_close_event(cid, c))\n"
            "            close_listener_registered = True\n"
            "        except Exception as exc:\n"
            "            _camoufox_debug(\"context_close_listener_failed\", session_id=self.session_id, context_id=context_id, error_type=type(exc).__name__, error_len=len(str(exc)), error_summary=_safe_text(exc, 300))\n",
            1,
        )
        text = text.replace(
            "            listener_registered=listener_registered,\n",
            "            listener_registered=page_listener_registered,\n"
            "            page_listener_registered=page_listener_registered,\n"
            "            close_listener_registered=close_listener_registered,\n",
            1,
        )
        handler = '''    def _handle_context_close_event(self, context_id: str, ctx: BrowserContext | None) -> None:
        started = time.perf_counter()
        pages_before = _context_page_count(ctx)
        page_ids = [
            pid for pid, meta in list(self.page_meta.items())
            if meta.get("context_id") == context_id and pid in self.pages
        ]
        for pid in page_ids:
            self._on_page_closed(pid, self.pages.get(pid), "context_close_event")
        if ctx is not None:
            self.context_ids.pop(id(ctx), None)
        if self.contexts.get(context_id) is ctx:
            self.contexts.pop(context_id, None)
        _camoufox_debug(
            "context_close_event",
            session_id=self.session_id,
            context_id=context_id,
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            pages_before=pages_before,
            pages_marked_closed=len(page_ids),
            registered_contexts=len(self.contexts),
            registered_pages=len(self.pages),
            active_page_id=self.active_page_id or "",
            browser_open=self.browser is not None,
            browser_connected=self._browser_connected(),
            process_tree=_process_tree_snapshot(),
        )

'''
        text = text.replace("    def _queue_pending_page_id", handler + "    def _queue_pending_page_id", 1)
    text = text.replace(
        '        page.on("close", lambda *_, pid=page_id: self._on_page_closed(pid))\n',
        '        page.on("close", lambda *_, pid=page_id, p=page: self._handle_page_close_event(p, pid))\n',
    )
    text = text.replace(
        '            page.on("crash", lambda *_, pid=page_id: _camoufox_debug("page_crashed", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id, page_count=len(self.pages), context_count=len(self.contexts)))\n',
        '            page.on("crash", lambda *_, pid=page_id, p=page: self._handle_page_crash_event(p, pid))\n',
    )
    if "self._page_terminal_ids: set[str] = set()" not in text:
        text = text.replace(
            "        self._listener_page_ids: set[str] = set()\n",
            "        self._listener_page_ids: set[str] = set()\n"
            "        self._page_terminal_ids: set[str] = set()\n",
        )
        text = text.replace(
            "        self._listener_page_ids.clear()\n",
            "        self._listener_page_ids.clear()\n"
            "        self._page_terminal_ids.clear()\n",
        )
    if "self._page_terminal_ids.discard(page_id)" not in text:
        text = text.replace(
            "        created = page_id not in self.pages\n"
            "        self.pages[page_id] = page\n",
            "        created = page_id not in self.pages\n"
            "        self._page_terminal_ids.discard(page_id)\n"
            "        self.pages[page_id] = page\n",
        )
    if "def _schedule_page_lifecycle_log" not in text:
        schedule_block = '''    def _schedule_page_lifecycle_log(self, event: str, page: Page | None, page_id: str, started: float | None = None, exc: Exception | None = None) -> None:
        async def emit() -> None:
            event_started = started or time.perf_counter()
            try:
                state = await self._launch_debug_snapshot(event, event_started, None, page=page, page_id=page_id, exc=exc)
                _camoufox_debug(
                    event,
                    session_id=self.session_id,
                    page_id=page_id,
                    elapsed_ms=int((time.perf_counter() - event_started) * 1000),
                    state=state,
                )
            except Exception as log_exc:
                _camoufox_debug(
                    f"{event}_log_failed",
                    session_id=self.session_id,
                    page_id=page_id,
                    error_type=type(log_exc).__name__,
                    error_len=len(str(log_exc)),
                    error_summary=_safe_text(log_exc),
                )
        try:
            asyncio.get_running_loop().create_task(emit())
        except RuntimeError as loop_exc:
            _camoufox_debug(
                f"{event}_log_unavailable",
                session_id=self.session_id,
                page_id=page_id,
                error_type=type(loop_exc).__name__,
                error_len=len(str(loop_exc)),
                error_summary=_safe_text(loop_exc),
                process_tree=_process_tree_snapshot(),
            )

'''
        lifecycle_anchor = "    def _handle_page_close_event" if "    def _handle_page_close_event" in text else "    def _on_page_closed"
        text = text.replace(lifecycle_anchor, schedule_block + lifecycle_anchor, 1)
    if "def _mark_page_terminal" not in text:
        terminal_block = '''    def _handle_page_close_event(self, page: Page | None, page_id: str) -> None:
        started = time.perf_counter()
        self._schedule_page_lifecycle_log("page_close_event", page, page_id, started)
        self._on_page_closed(page_id, page, "close_event")

    def _handle_page_crash_event(self, page: Page | None, page_id: str) -> None:
        self._schedule_page_lifecycle_log("page_crash_event", page, page_id)
        self._on_page_crashed(page_id, page, "crash_event")

    def _next_live_page_id(self, excluded_page_id: str) -> str | None:
        for candidate_id, candidate in list(self.pages.items()):
            if candidate_id == excluded_page_id:
                continue
            if not self._page_closed(candidate):
                return candidate_id
        return None

    def _mark_page_terminal(self, page_id: str, page: Page | None, reason: str, source: str, exc: Exception | None = None) -> bool:
        already_terminal = page_id in self._page_terminal_ids
        stored_page = self.pages.pop(page_id, None)
        page = page or stored_page
        meta = self.page_meta.setdefault(page_id, {"page_id": page_id})
        if bool(meta.get("closed")) and stored_page is None:
            already_terminal = True
        now_ms = int(time.time() * 1000)
        meta["closed"] = True
        meta["closed_ms"] = meta.get("closed_ms") or now_ms
        meta["terminal_reason"] = reason
        meta["terminal_source"] = source
        if reason == "crashed":
            meta["crashed"] = True
            meta["crashed_ms"] = meta.get("crashed_ms") or now_ms
        guid = meta.get("guid") or (self._page_guid(page) if page else "")
        if guid:
            self._page_guid_to_id.pop(str(guid), None)
        self._listener_page_ids.discard(page_id)
        self._page_terminal_ids.add(page_id)
        if self.active_page_id == page_id:
            self.active_page_id = self._next_live_page_id(page_id)
            self.active_page_name = self.active_page_id
        event_name = "page_crashed" if reason == "crashed" else "page_closed"
        _camoufox_debug(
            event_name,
            session_id=self.session_id,
            page_id=page_id,
            active=self.active_page_id or "",
            page_count=len(self.pages),
            context_count=len(self.contexts),
            browser_open=self.browser is not None,
            browser_connected=self._browser_connected(),
            guid=str(guid or ""),
            meta_context_id=meta.get("context_id", ""),
            duplicate=already_terminal,
            reason=reason,
            source=source,
            error_type=type(exc).__name__ if exc else "",
            error_summary=_safe_text(exc, 300) if exc else "",
            process_tree=_process_tree_snapshot(),
        )
        return not already_terminal

    def _on_page_closed(self, page_id: str, page: Page | None = None, source: str = "manual", exc: Exception | None = None) -> bool:
        return self._mark_page_terminal(page_id, page, "closed", source, exc)

    def _on_page_crashed(self, page_id: str, page: Page | None = None, source: str = "manual", exc: Exception | None = None) -> bool:
        return self._mark_page_terminal(page_id, page, "crashed", source, exc)

    def page_id_for'''
        text = re.sub(
            r"    def _handle_page_close_event\(self, page: Page \| None, page_id: str\) -> None:\n(?:    .+\n)+?\n    def page_id_for",
            terminal_block,
            text,
            count=1,
        )
        if "def _mark_page_terminal" not in text:
            text = re.sub(
                r"    def _on_page_closed\(self, page_id: str\) -> None:\n(?:    .+\n)+?\n    def page_id_for",
                terminal_block,
                text,
                count=1,
            )
    if "close_page_target_closed" not in text:
        text = text.replace(
            '        except Exception as exc:\n'
            '            _camoufox_debug(\n'
            '                "close_page_failed",\n',
            '        except Exception as exc:\n'
            '            if _target_closed_error(exc):\n'
            '                self._on_page_closed(pid, page, "close_page_target_closed", exc)\n'
            '                _camoufox_debug(\n'
            '                    "close_page_target_closed",\n'
            '                    session_id=self.session_id,\n'
            '                    page_id=pid,\n'
            '                    elapsed_ms=int((time.perf_counter() - started) * 1000),\n'
            '                    state=await self._launch_debug_snapshot("close_page_target_closed", started, 15000, page=page, page_id=pid, exc=exc),\n'
            '                )\n'
            '                return {"status": "closed", "page_id": pid, "active_page_id": self.active_page_id, "page_count": len(self.pages)}\n'
            '            _camoufox_debug(\n'
            '                "close_page_failed",\n',
            1,
        )
        text = text.replace(
            '        self._on_page_closed(pid)\n'
            '        _camoufox_debug(\n'
            '            "close_page_done",\n',
            '        self._on_page_closed(pid, page, "close_page")\n'
            '        _camoufox_debug(\n'
            '            "close_page_done",\n',
            1,
        )
    text = text.replace(
        "            self._on_page_closed(pid)\n"
        "            raise RuntimeError(f\"Page is closed: {pid}\")\n",
        "            self._on_page_closed(pid, page, \"resolve_closed\")\n"
        "            raise RuntimeError(f\"Page is closed: {pid}\")\n",
    )
    required = (
        "def _flag_enabled",
        "AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK",
        "AIDA_CAMOUFOX_BRIDGE_PATCH_ID",
        "aida_fast_visible_policy_v1",
        "aida_bridge_patch_active",
        "aida_launch_policy_resolved",
        "aida_fast_visible_fallback_ignored",
        "selected_launch_path",
        "block_service_workers",
        '"browser_ready_ms": elapsed_ms',
        '"camoufox_launch_ms": elapsed_ms',
        "def _mark_page_terminal",
        "context_close_event",
        "close_page_target_closed",
        "page_crashed",
    )
    for marker in required:
        if marker not in text:
            fail(f"browser stability validation missing {marker}")
    forbidden = (
        'return bool(cfg.get("aida_fast_visible_launch", True))',
        "fast_visible_" + "firefox_" + "compat",
        "launch_" + "fast_visible" + "_compat_selected",
        "return " + "_flag_enabled(requested)",
        'context_options: dict[str, Any] = {"service_workers": "block"}',
        'ctx = await self.browser.new_context(service_workers="block")',
    )
    for marker in forbidden:
        if marker in text:
            fail(f"browser stability validation forbidden marker {marker}")
    return text


def patch_browser(path: pathlib.Path) -> None:
    text = patch_browser_debug_helper(read_text(path))
    if "self._aida_multipage_patch = 4" in text:
        updated = text
        updated = updated.replace(
            "        page.on(\"close\", lambda pid=page_id: self._on_page_closed(pid))\n",
            "        page.on(\"close\", lambda *_, pid=page_id: self._on_page_closed(pid))\n",
        )
        updated = updated.replace(
            "            page.on(\"crash\", lambda pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id, page_count=len(self.pages), context_count=len(self.contexts)))\n",
            "            page.on(\"crash\", lambda *_, pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id, page_count=len(self.pages), context_count=len(self.contexts)))\n",
        )
        updated = updated.replace(
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        page = await ctx.new_page()\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        try:\n"
            "            page = await ctx.new_page()\n"
            "        except Exception:\n"
            "            self._discard_pending_page_id(requested_context_id, page_id)\n"
            "            raise\n"
            "        privacy_info = await _verify_page_privacy(page, self._context_plan)\n"
            "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
            "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
            "        if not privacy_info.get(\"webrtc_blocked\") or not privacy_info.get(\"ice_probe_ok\") or privacy_info.get(\"ice_candidate_leak_detected\"):\n"
            "            with contextlib.suppress(Exception):\n"
            "                await page.close()\n"
            "            raise RuntimeError(\"Camoufox privacy verification failed\")\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
        )
        if "page_privacy_verified" not in updated:
            updated = replace_once(
                updated,
                "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n",
                "        privacy_info = await _verify_page_privacy(page, self._context_plan)\n"
                "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
                "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
                "        if not privacy_info.get(\"webrtc_blocked\") or not privacy_info.get(\"ice_probe_ok\") or privacy_info.get(\"ice_candidate_leak_detected\"):\n"
                "            with contextlib.suppress(Exception):\n"
                "                await page.close()\n"
                "            raise RuntimeError(\"Camoufox privacy verification failed\")\n"
                "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n",
                "browser v4 page privacy guard",
            )
        updated = patch_browser_launch_deadline_diagnostics(updated)
        updated = patch_browser_camoufox_stability(updated)
        updated = patch_browser_pending_activation(updated)
        updated = patch_browser_new_page_diagnostics(updated)
        updated = patch_browser_debug_helper(updated)
        validate_browser_addon_policy_contract(path, updated)
        validate_browser_launch_budget_contract(path, updated)
        validate_browser_context_viewport_contract(path, updated)
        if updated != text:
            write_text(path, updated)
        return
    if "self._aida_multipage_patch = 3" in text:
        updated = text.replace("        self._aida_multipage_patch = 3\n", "        self._aida_multipage_patch = 4\n")
        updated = updated.replace(
            "        page.on(\"close\", lambda pid=page_id: self._on_page_closed(pid))\n",
            "        page.on(\"close\", lambda *_, pid=page_id: self._on_page_closed(pid))\n",
        )
        updated = updated.replace(
            "            page.on(\"crash\", lambda pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id, page_count=len(self.pages), context_count=len(self.contexts)))\n",
            "            page.on(\"crash\", lambda *_, pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id, page_count=len(self.pages), context_count=len(self.contexts)))\n",
        )
        updated = updated.replace(
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        page = await ctx.new_page()\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        try:\n"
            "            page = await ctx.new_page()\n"
            "        except Exception:\n"
            "            self._discard_pending_page_id(requested_context_id, page_id)\n"
            "            raise\n"
            "        privacy_info = await _verify_page_privacy(page, self._context_plan)\n"
            "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
            "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
            "        if not privacy_info.get(\"webrtc_blocked\") or not privacy_info.get(\"ice_probe_ok\") or privacy_info.get(\"ice_candidate_leak_detected\"):\n"
            "            with contextlib.suppress(Exception):\n"
            "                await page.close()\n"
            "            raise RuntimeError(\"Camoufox privacy verification failed\")\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
        )
        if "page_privacy_verified" not in updated:
            updated = replace_once(
                updated,
                "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n",
                "        privacy_info = await _verify_page_privacy(page, self._context_plan)\n"
                "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
                "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
                "        if not privacy_info.get(\"webrtc_blocked\") or not privacy_info.get(\"ice_probe_ok\") or privacy_info.get(\"ice_candidate_leak_detected\"):\n"
                "            with contextlib.suppress(Exception):\n"
                "                await page.close()\n"
                "            raise RuntimeError(\"Camoufox privacy verification failed\")\n"
                "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n",
                "browser v3 page privacy guard",
            )
        updated = patch_browser_launch_deadline_diagnostics(updated)
        updated = patch_browser_camoufox_stability(updated)
        updated = patch_browser_pending_activation(updated)
        updated = patch_browser_new_page_diagnostics(updated)
        updated = patch_browser_debug_helper(updated)
        validate_browser_addon_policy_contract(path, updated)
        validate_browser_launch_budget_contract(path, updated)
        validate_browser_context_viewport_contract(path, updated)
        if updated != text:
            write_text(path, updated)
        return
    if "self._aida_multipage_patch = 2" in text:
        updated = text.replace("        self._aida_multipage_patch = 2\n", "        self._aida_multipage_patch = 4\n")
        if "self._pending_page_ids_by_context" not in updated:
            updated = replace_once(
                updated,
                "        self._listener_page_ids: set[str] = set()\n",
                "        self._listener_page_ids: set[str] = set()\n"
                "        self._pending_page_ids_by_context: dict[str, list[str]] = {}\n",
                "browser pending page id state",
            )
        if "def _queue_pending_page_id" not in updated:
            updated = replace_once(
                updated,
                "    def _context_id_for_page(self, page: Page | None) -> str:\n",
                "    def _queue_pending_page_id(self, context_id: str, page_id: str | None) -> None:\n"
                "        pid = self._slug(page_id) if page_id else \"\"\n"
                "        if pid:\n"
                "            self._pending_page_ids_by_context.setdefault(context_id or \"default\", []).append(pid)\n\n"
                "    def _pop_pending_page_id(self, context_id: str) -> str | None:\n"
                "        queue = self._pending_page_ids_by_context.get(context_id or \"default\")\n"
                "        if not queue:\n"
                "            return None\n"
                "        pid = queue.pop(0)\n"
                "        if not queue:\n"
                "            self._pending_page_ids_by_context.pop(context_id or \"default\", None)\n"
                "        return pid\n\n"
                "    def _discard_pending_page_id(self, context_id: str, page_id: str | None) -> None:\n"
                "        pid = self._slug(page_id) if page_id else \"\"\n"
                "        queue = self._pending_page_ids_by_context.get(context_id or \"default\")\n"
                "        if pid and queue and pid in queue:\n"
                "            queue.remove(pid)\n"
                "            if not queue:\n"
                "                self._pending_page_ids_by_context.pop(context_id or \"default\", None)\n\n"
                "    def _context_id_for_page(self, page: Page | None) -> str:\n",
                "browser pending page id helpers",
            )
        updated = updated.replace(
            "            ctx.on(\"page\", lambda page, cid=context_id: self._register_page(page, None, True, \"context_page\", cid))\n",
            "            ctx.on(\"page\", lambda page, cid=context_id: self._register_page(page, self._pop_pending_page_id(cid), True, \"context_page\", cid))\n",
        )
        updated = updated.replace(
            "        ctx = self.contexts.get(context_id or \"default\") or await self.get_active_context()\n"
            "        page = await ctx.new_page()\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", context_id or self._context_id_for_page(page))\n",
            "        requested_context_id = context_id or \"default\"\n"
            "        ctx = self.contexts.get(requested_context_id) or await self.get_active_context()\n"
            "        requested_context_id = context_id or self.context_ids.get(id(ctx), \"default\")\n"
            "        self._queue_pending_page_id(requested_context_id, page_id)\n"
            "        try:\n"
            "            page = await ctx.new_page()\n"
            "        except Exception:\n"
            "            self._discard_pending_page_id(requested_context_id, page_id)\n"
            "            raise\n"
            "        privacy_info = await _verify_page_privacy(page, self._context_plan)\n"
            "        privacy_page_id = self.page_id_for(page) or (page_id or \"\")\n"
            "        _camoufox_debug(\"page_privacy_verified\", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)\n"
            "        if not privacy_info.get(\"webrtc_blocked\") or not privacy_info.get(\"ice_probe_ok\") or privacy_info.get(\"ice_candidate_leak_detected\"):\n"
            "            with contextlib.suppress(Exception):\n"
            "                await page.close()\n"
            "            raise RuntimeError(\"Camoufox privacy verification failed\")\n"
            "        pid = self._register_page(page, page_id, make_active, \"new_page\", requested_context_id)\n"
            "        self._discard_pending_page_id(requested_context_id, page_id)\n",
        )
        if "self._pending_page_ids_by_context" not in updated or "self._pop_pending_page_id(cid)" not in updated or "page_privacy_verified" not in updated:
            fail("browser v2 upgrade missing pending page id support")
        updated = patch_browser_launch_deadline_diagnostics(updated)
        updated = patch_browser_camoufox_stability(updated)
        updated = patch_browser_pending_activation(updated)
        updated = patch_browser_new_page_diagnostics(updated)
        updated = patch_browser_debug_helper(updated)
        validate_browser_addon_policy_contract(path, updated)
        validate_browser_launch_budget_contract(path, updated)
        validate_browser_context_viewport_contract(path, updated)
        write_text(path, updated)
        return
    text = replace_once(
        text,
        "        self.pages: dict[str, Page] = {}\n"
        "        self.active_page_name: str | None = None\n"
        "        self._cm = None  # AsyncCamoufox context manager\n",
        "        self.pages: dict[str, Page] = {}\n"
        "        self.page_meta: dict[str, dict[str, Any]] = {}\n"
        "        self.context_ids: dict[int, str] = {}\n"
        "        self._page_guid_to_id: dict[str, str] = {}\n"
        "        self._listener_page_ids: set[str] = set()\n"
        "        self._pending_page_ids_by_context: dict[str, list[str]] = {}\n"
        "        self._page_counter = 0\n"
        "        self.active_page_name: str | None = None\n"
        "        self.active_page_id: str | None = None\n"
        "        self.session_id: str = _os.environ.get(\"AIDA_CAMOUFOX_SESSION_ID\", \"default\") or \"default\"\n"
        "        self._aida_multipage_patch = 4\n"
        "        self._cm = None  # AsyncCamoufox context manager\n",
        "browser init multipage state",
    )
    text = replace_once(
        text,
        "        self._nav_responses: list[dict] = []",
        "        self._nav_responses: list[dict] = []\n"
        "        self._nav_responses_by_page: dict[str, list[dict]] = {}",
        "browser nav response state",
    )
    text = replace_browser_already_running_summary(text)
    text = replace_browser_already_running_fields(text)
    if "self._register_context(\"default\", ctx)" not in text:
        text = replace_once(
            text,
            "            self.contexts[\"default\"] = ctx\n",
            "            self.contexts[\"default\"] = ctx\n"
            "            self._register_context(\"default\", ctx)\n",
            "browser launch context register",
        )
    text = replace_once(
        text,
        "            self._attach_listeners(page)\n"
        "            self.pages[\"default\"] = page\n"
        "            self.active_page_name = \"default\"\n",
        "            for existing_page in list(ctx.pages):\n"
        "                self._register_page(existing_page, \"default\" if existing_page is page else None, existing_page is page, \"launch_existing\")\n"
        "            page_id = self._register_page(page, \"default\", True, \"launch\")\n"
        "            page = self.pages[page_id]\n",
        "browser launch page register",
    )
    text = replace_once(
        text,
        "                \"pages\": len(self.pages),\n"
        "                \"profile\": profile_info,\n",
        "                \"pages\": len(self.pages),\n"
        "                \"active_page_id\": self.active_page_id,\n"
        "                \"profile\": profile_info,\n",
        "browser launch diagnostics page id",
    )
    text = replace_once(
        text,
        "                \"pages\": list(self.pages.keys()),\n"
        "                \"window_width\": window_size[0],\n",
        "                \"session_id\": self.session_id,\n"
        "                \"active_page\": self.active_page_id,\n"
        "                \"active_page_id\": self.active_page_id,\n"
        "                \"page_count\": len(self.pages),\n"
        "                \"pages\": await self.list_pages(),\n"
        "                \"window_width\": window_size[0],\n",
        "browser launch result pages",
    )
    text = text.replace(
        "            self.pages.clear()\n"
        "            self.active_page_name = None\n",
        "            self.pages.clear()\n"
        "            self.page_meta.clear()\n"
        "            self.context_ids.clear()\n"
        "            self._page_guid_to_id.clear()\n"
        "            self._listener_page_ids.clear()\n"
        "            self.active_page_name = None\n"
        "            self.active_page_id = None\n",
    )
    text = patch_browser_launch_deadline_diagnostics(text)
    helper_anchor = (
        "    def remove_persistent_script(self, name: str) -> bool:\n"
        "        \"\"\"Remove a persistent script by name. Returns True if found.\"\"\"\n"
        "        before = len(self._persistent_scripts)\n"
        "        self._persistent_scripts = [s for s in self._persistent_scripts if s[\"name\"] != name]\n"
        "        return len(self._persistent_scripts) < before\n\n"
    )
    helpers = r'''    def _page_guid(self, page: Page) -> str:
        impl = getattr(page, "_impl_obj", None)
        return str(getattr(page, "_guid", "") or getattr(impl, "_guid", "") or "")

    def _page_closed(self, page: Page) -> bool:
        try:
            return bool(page.is_closed())
        except Exception:
            return True

    def _slug(self, value: str | None) -> str:
        value = str(value or "page").strip().lower()
        value = _re.sub(r"[^a-z0-9_.:-]+", "-", value).strip("-")
        return value[:48] or "page"

    def _next_page_id(self, hint: str | None = None) -> str:
        base = self._slug(hint)
        while True:
            self._page_counter += 1
            candidate = f"{base}-{self._page_counter:04d}"
            if candidate not in self.pages and candidate not in self.page_meta:
                return candidate

    def _context_id_for_page(self, page: Page | None) -> str:
        if page is None:
            return "default"
        try:
            key = id(page.context)
            if key in self.context_ids:
                return self.context_ids[key]
        except Exception:
            pass
        return "default"

    def _register_context(self, context_id: str, ctx: BrowserContext) -> None:
        self.context_ids[id(ctx)] = context_id
        try:
            ctx.on("page", lambda page, cid=context_id: self._register_page(page, self._pop_pending_page_id(cid), True, "context_page", cid))
        except Exception as exc:
            _camoufox_debug("context_listener_failed", session_id=self.session_id, context_id=context_id, error_type=type(exc).__name__, error=_safe_text(exc, 300))
        _camoufox_debug("context_registered", session_id=self.session_id, context_id=context_id, pages=len(getattr(ctx, "pages", []) or []))

    def _queue_pending_page_id(self, context_id: str, page_id: str | None) -> None:
        pid = self._slug(page_id) if page_id else ""
        if pid:
            self._pending_page_ids_by_context.setdefault(context_id or "default", []).append(pid)

    def _pop_pending_page_id(self, context_id: str) -> str | None:
        queue = self._pending_page_ids_by_context.get(context_id or "default")
        if not queue:
            return None
        pid = queue.pop(0)
        if not queue:
            self._pending_page_ids_by_context.pop(context_id or "default", None)
        return pid

    def _discard_pending_page_id(self, context_id: str, page_id: str | None) -> None:
        pid = self._slug(page_id) if page_id else ""
        queue = self._pending_page_ids_by_context.get(context_id or "default")
        if pid and queue and pid in queue:
            queue.remove(pid)
            if not queue:
                self._pending_page_ids_by_context.pop(context_id or "default", None)

    def _register_page(self, page: Page, preferred_id: str | None = None, make_active: bool = False, source: str = "register", context_id: str | None = None) -> str:
        guid = self._page_guid(page)
        if guid and guid in self._page_guid_to_id:
            page_id = self._page_guid_to_id[guid]
        else:
            existing = None
            for pid, known in self.pages.items():
                if known is page:
                    existing = pid
                    break
            page_id = existing or (self._slug(preferred_id) if preferred_id and preferred_id not in self.pages and preferred_id not in self.page_meta else self._next_page_id(preferred_id))
        context_id = context_id or self._context_id_for_page(page)
        created = page_id not in self.pages
        self.pages[page_id] = page
        if guid:
            self._page_guid_to_id[guid] = page_id
        meta = self.page_meta.setdefault(page_id, {})
        meta.update({
            "page_id": page_id,
            "context_id": context_id,
            "guid": guid,
            "created_ms": meta.get("created_ms") or int(time.time() * 1000),
            "last_used_ms": int(time.time() * 1000),
            "closed": False,
            "source": source,
        })
        if page_id not in self._listener_page_ids:
            self._listener_page_ids.add(page_id)
            self._attach_listeners(page, page_id)
        if make_active or not self.active_page_id:
            self.active_page_id = page_id
            self.active_page_name = page_id
        _camoufox_debug("page_registered", session_id=self.session_id, page_id=page_id, context_id=context_id, guid=guid, created=created, active=self.active_page_id, source=source, page_count=len(self.pages))
        return page_id

    def _on_page_closed(self, page_id: str) -> None:
        page = self.pages.pop(page_id, None)
        meta = self.page_meta.setdefault(page_id, {"page_id": page_id})
        meta["closed"] = True
        meta["closed_ms"] = int(time.time() * 1000)
        guid = meta.get("guid") or (self._page_guid(page) if page else "")
        if guid:
            self._page_guid_to_id.pop(str(guid), None)
        if self.active_page_id == page_id:
            self.active_page_id = next(iter(self.pages.keys()), None)
            self.active_page_name = self.active_page_id
        _camoufox_debug("page_closed", session_id=self.session_id, page_id=page_id, active=self.active_page_id or "", page_count=len(self.pages))

    def page_id_for(self, page: Page | None) -> str | None:
        if page is None:
            return None
        guid = self._page_guid(page)
        if guid and guid in self._page_guid_to_id:
            return self._page_guid_to_id[guid]
        for pid, known in self.pages.items():
            if known is page:
                return pid
        return None

    async def page_summary(self, page: Page | None = None, page_id: str | None = None) -> dict[str, Any]:
        if page is None:
            page = await self.resolve_page(page_id)
        page_id = page_id or self.page_id_for(page) or self._register_page(page, None, False, "summary")
        meta = dict(self.page_meta.get(page_id, {}))
        url = ""
        title = ""
        closed = True
        title_error = None
        try:
            closed = self._page_closed(page)
            if not closed:
                url = str(page.url or "")
                try:
                    title = await asyncio.wait_for(page.title(), timeout=3)
                except Exception as exc:
                    title_error = _safe_text(exc, 300)
        except Exception as exc:
            title_error = _safe_text(exc, 300)
        out = {
            "session_id": self.session_id,
            "page_id": page_id,
            "context_id": meta.get("context_id") or self._context_id_for_page(page),
            "active": page_id == self.active_page_id,
            "closed": closed,
            "url": url,
            "title": title,
            "guid": meta.get("guid") or self._page_guid(page),
            "created_ms": meta.get("created_ms"),
            "last_used_ms": meta.get("last_used_ms"),
        }
        if title_error:
            out["title_error"] = title_error
        return out

    async def page_envelope(self, page: Page | None = None, page_id: str | None = None) -> dict[str, Any]:
        if page is None:
            page = await self.resolve_page(page_id)
        pid = self.page_id_for(page) or page_id or self._register_page(page, None, False, "envelope")
        summary = await self.page_summary(page, pid)
        return {
            "session_id": self.session_id,
            "page_id": pid,
            "active_page_id": self.active_page_id,
            "page_count": len(self.pages),
            "url": summary.get("url", ""),
            "title": summary.get("title", ""),
        }

    async def list_pages(self) -> list[dict[str, Any]]:
        await self._ensure_browser()
        out = []
        for page_id, page in list(self.pages.items()):
            out.append(await self.page_summary(page, page_id))
        _camoufox_debug("pages_listed", session_id=self.session_id, active_page_id=self.active_page_id or "", page_count=len(out))
        return out

    async def new_page(self, url: str | None = None, page_id: str | None = None, make_active: bool = True, context_id: str | None = None) -> dict[str, Any]:
        await self._ensure_browser()
        requested_context_id = context_id or "default"
        ctx = self.contexts.get(requested_context_id) or await self.get_active_context()
        requested_context_id = context_id or self.context_ids.get(id(ctx), "default")
        self._queue_pending_page_id(requested_context_id, page_id)
        try:
            page = await ctx.new_page()
        except Exception:
            self._discard_pending_page_id(requested_context_id, page_id)
            raise
        privacy_info = await _verify_page_privacy(page, self._context_plan)
        privacy_page_id = self.page_id_for(page) or (page_id or "")
        _camoufox_debug("page_privacy_verified", session_id=self.session_id, page_id=privacy_page_id, **privacy_info)
        if not privacy_info.get("webrtc_blocked") or not privacy_info.get("ice_probe_ok") or privacy_info.get("ice_candidate_leak_detected"):
            with contextlib.suppress(Exception):
                await page.close()
            raise RuntimeError("Camoufox privacy verification failed")
        pid = self._register_page(page, page_id, make_active, "new_page", requested_context_id)
        self._discard_pending_page_id(requested_context_id, page_id)
        if url:
            await page.goto(url, wait_until="load", timeout=30000)
        summary = await self.page_summary(page, pid)
        _camoufox_debug("page_created", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id or "", url_len=len(summary.get("url", "")), page_count=len(self.pages))
        return {"status": "created", "page": summary, "page_id": pid, "active_page_id": self.active_page_id, "page_count": len(self.pages)}

    async def select_page(self, page_id: str) -> dict[str, Any]:
        page = await self.resolve_page(page_id)
        pid = self.page_id_for(page) or page_id
        self.active_page_id = pid
        self.active_page_name = pid
        meta = self.page_meta.setdefault(pid, {"page_id": pid})
        meta["last_used_ms"] = int(time.time() * 1000)
        summary = await self.page_summary(page, pid)
        _camoufox_debug("page_selected", session_id=self.session_id, page_id=pid, url_len=len(summary.get("url", "")), page_count=len(self.pages))
        return {"status": "selected", "page": summary, "page_id": pid, "active_page_id": self.active_page_id, "page_count": len(self.pages)}

    async def close_page(self, page_id: str) -> dict[str, Any]:
        page = await self.resolve_page(page_id)
        pid = self.page_id_for(page) or page_id
        await page.close()
        self._on_page_closed(pid)
        return {"status": "closed", "page_id": pid, "active_page_id": self.active_page_id, "page_count": len(self.pages)}

    async def resolve_page(self, page_id: str | None = None) -> Page:
        await self._ensure_browser()
        pid = str(page_id or self.active_page_id or self.active_page_name or "default")
        page = self.pages.get(pid)
        if page is None and pid == "active" and self.active_page_id:
            page = self.pages.get(self.active_page_id)
            pid = self.active_page_id
        if page is None and not page_id and self.pages:
            pid, page = next(iter(self.pages.items()))
        if page is None:
            raise RuntimeError(f"No page available for page_id={pid!r}. Call launch_browser or new_page first.")
        if self._page_closed(page):
            self._on_page_closed(pid)
            raise RuntimeError(f"Page is closed: {pid}")
        self.active_page_id = pid if not page_id else self.active_page_id
        self.active_page_name = self.active_page_id
        self.page_meta.setdefault(pid, {"page_id": pid})["last_used_ms"] = int(time.time() * 1000)
        return page

'''
    text = replace_once(text, helper_anchor, helper_anchor + helpers, "browser helper insertion")
    text = replace_once(
        text,
        "    def _attach_listeners(self, page: Page) -> None:\n"
        "        \"\"\"Attach console, network, and trace-collection listeners to a page.\"\"\"\n"
        "        page.on(\"console\", self._on_console)\n"
        "        page.on(\"request\", self._on_request)\n"
        "        page.on(\"response\", self._on_response_async)\n"
        "        page.on(\"response\", self._on_response_for_nav)\n",
        "    def _attach_listeners(self, page: Page, page_id: str | None = None) -> None:\n"
        "        page_id = page_id or self.page_id_for(page) or self._register_page(page, None, False, \"listener_attach\")\n"
        "        page.on(\"console\", lambda msg, pid=page_id: self._on_console(msg, pid))\n"
        "        page.on(\"request\", lambda req, pid=page_id: self._on_request(req, pid))\n"
        "        page.on(\"response\", lambda resp, pid=page_id: self._on_response_async(resp, pid))\n"
        "        page.on(\"response\", lambda resp, pid=page_id: self._on_response_for_nav(resp, pid))\n"
        "        page.on(\"close\", lambda *_, pid=page_id: self._on_page_closed(pid))\n"
        "        with contextlib.suppress(Exception):\n"
        "            page.on(\"crash\", lambda *_, pid=page_id: _camoufox_debug(\"page_crashed\", session_id=self.session_id, page_id=pid, active_page_id=self.active_page_id, page_count=len(self.pages), context_count=len(self.contexts)))\n",
        "browser attach listeners",
    )
    text = replace_once(
        text,
        "    def _on_console(self, msg) -> None:\n",
        "    def _on_console(self, msg, page_id: str | None = None) -> None:\n",
        "browser console signature",
    )
    text = replace_once(
        text,
        "            \"timestamp\": int(time.time() * 1000),\n"
        "            \"location\": str(msg.location) if hasattr(msg, \"location\") else None,\n",
        "            \"timestamp\": int(time.time() * 1000),\n"
        "            \"page_id\": page_id,\n"
        "            \"context_id\": self.page_meta.get(page_id or \"\", {}).get(\"context_id\"),\n"
        "            \"location\": str(msg.location) if hasattr(msg, \"location\") else None,\n",
        "browser console fields",
    )
    text = replace_once(
        text,
        "    def _on_request(self, req) -> None:\n",
        "    def _on_request(self, req, page_id: str | None = None) -> None:\n",
        "browser request signature",
    )
    text = replace_once(
        text,
        "            \"id\": self._request_id_counter,\n"
        "            \"url\": req.url,\n",
        "            \"id\": self._request_id_counter,\n"
        "            \"page_id\": page_id,\n"
        "            \"context_id\": self.page_meta.get(page_id or \"\", {}).get(\"context_id\"),\n"
        "            \"url\": req.url,\n",
        "browser request fields",
    )
    text = replace_once(
        text,
        "    def _on_response_async(self, resp) -> None:\n"
        "        \"\"\"Handle response events, optionally capturing body asynchronously.\"\"\"\n",
        "    def _on_response_async(self, resp, page_id: str | None = None) -> None:\n",
        "browser response signature",
    )
    text = replace_once(
        text,
        "            if entry[\"url\"] == resp.url and entry[\"status\"] is None:\n",
        "            if entry[\"url\"] == resp.url and entry[\"status\"] is None and (page_id is None or entry.get(\"page_id\") == page_id):\n",
        "browser response page match",
    )
    if "response_body_task" not in text:
        text = replace_once(
            text,
            "                    asyncio.ensure_future(self._fetch_response_body(resp, entry))\n",
            "                    entry[\"response_body_task\"] = asyncio.ensure_future(self._fetch_response_body(resp, entry))\n",
            "browser response body task",
        )
    text = replace_once(
        text,
        "    def _on_response_for_nav(self, resp) -> None:\n"
        "        \"\"\"Record every response during a navigation for final_status resolution.\"\"\"\n"
        "        try:\n"
        "            self._nav_responses.append({\n"
        "                \"url\": resp.url,\n"
        "                \"status\": resp.status,\n"
        "                \"resource_type\": getattr(resp.request, \"resource_type\", None) if resp.request else None,\n"
        "                \"ts\": int(time.time() * 1000),\n"
        "            })\n"
        "            # Keep only the last 100\n"
        "            if len(self._nav_responses) > 100:\n"
        "                self._nav_responses = self._nav_responses[-100:]\n"
        "        except Exception:\n"
        "            pass\n\n"
        "    def reset_nav_responses(self) -> None:\n"
        "        self._nav_responses = []\n",
        "    def _on_response_for_nav(self, resp, page_id: str | None = None) -> None:\n"
        "        try:\n"
        "            entry = {\n"
        "                \"url\": resp.url,\n"
        "                \"status\": resp.status,\n"
        "                \"resource_type\": getattr(resp.request, \"resource_type\", None) if resp.request else None,\n"
        "                \"page_id\": page_id,\n"
        "                \"ts\": int(time.time() * 1000),\n"
        "            }\n"
        "            self._nav_responses.append(entry)\n"
        "            if page_id:\n"
        "                page_chain = self._nav_responses_by_page.setdefault(page_id, [])\n"
        "                page_chain.append(entry)\n"
        "                if len(page_chain) > 100:\n"
        "                    self._nav_responses_by_page[page_id] = page_chain[-100:]\n"
        "            if len(self._nav_responses) > 100:\n"
        "                self._nav_responses = self._nav_responses[-100:]\n"
        "        except Exception:\n"
        "            pass\n\n"
        "    def reset_nav_responses(self, page_id: str | None = None) -> None:\n"
        "        if page_id:\n"
        "            self._nav_responses_by_page[page_id] = []\n"
        "            self._nav_responses = [r for r in self._nav_responses if r.get(\"page_id\") != page_id]\n"
        "        else:\n"
        "            self._nav_responses = []\n"
        "            self._nav_responses_by_page.clear()\n\n"
        "    def nav_responses_for_page(self, page_id: str | None = None) -> list[dict]:\n"
        "        if page_id:\n"
        "            return list(self._nav_responses_by_page.get(page_id, []))\n"
        "        return list(self._nav_responses)\n",
        "browser nav response methods",
    )
    if "return {\"status\": \"created\", \"context\": name, \"mode\": mode, \"page_id\": page_id" not in text:
        current_create_context = (
            "        self.contexts[name] = ctx\n"
            "        page = await _await_no_cancel_wait(ctx.new_page(), timeout=30.0)\n"
            "        if self._context_plan:\n"
            "            await _verify_page_privacy(page, self._context_plan)\n"
            "        self._attach_listeners(page)\n"
            "        self.pages[name] = page\n"
            "        self.active_page_name = name\n"
            "        return {\"status\": \"created\", \"context\": name, \"mode\": mode}\n"
        )
        patched_create_context = (
            "        self.contexts[name] = ctx\n"
            "        self._register_context(name, ctx)\n"
            "        page = await _await_no_cancel_wait(ctx.new_page(), timeout=30.0)\n"
            "        if self._context_plan:\n"
            "            await _verify_page_privacy(page, self._context_plan)\n"
            "        page_id = self._register_page(page, name, True, \"create_context\", name)\n"
            "        return {\"status\": \"created\", \"context\": name, \"mode\": mode, \"page_id\": page_id, \"active_page_id\": self.active_page_id, \"page_count\": len(self.pages)}\n"
        )
        if current_create_context in text:
            text = text.replace(current_create_context, patched_create_context, 1)
        else:
            text = replace_once(
                text,
                "        self.contexts[name] = ctx\n"
                "        page = await ctx.new_page()\n"
                "        self._attach_listeners(page)\n"
                "        self.pages[name] = page\n"
                "        self.active_page_name = name\n"
                "        return {\"status\": \"created\", \"context\": name, \"mode\": mode}\n",
                "        self.contexts[name] = ctx\n"
                "        self._register_context(name, ctx)\n"
                "        page = await ctx.new_page()\n"
                "        page_id = self._register_page(page, name, True, \"create_context\", name)\n"
                "        return {\"status\": \"created\", \"context\": name, \"mode\": mode, \"page_id\": page_id, \"active_page_id\": self.active_page_id, \"page_count\": len(self.pages)}\n",
                "browser create_context page register",
            )
    text = replace_once(
        text,
        "        if self.active_page_name and self.active_page_name in self.pages:\n"
        "            return self.pages[self.active_page_name].context\n",
        "        if self.active_page_id and self.active_page_id in self.pages:\n"
        "            return self.pages[self.active_page_id].context\n",
        "browser active context",
    )
    text = replace_once(
        text,
        "        if self.active_page_name and self.active_page_name in self.pages:\n"
        "            return self.pages[self.active_page_name]\n"
        "        raise RuntimeError(\"No active page available. Call launch_browser first.\")\n",
        "        return await self.resolve_page(None)\n",
        "browser get active page",
    )
    text = text.replace(
        "        self._nav_responses.clear()\n"
        "        self._route_handlers.clear()\n",
        "        self._nav_responses.clear()\n"
        "        self._nav_responses_by_page.clear()\n"
        "        self._route_handlers.clear()\n",
    )
    text = patch_browser_camoufox_stability(text)
    text = patch_browser_pending_activation(text)
    text = patch_browser_new_page_diagnostics(text)
    text = patch_browser_debug_helper(text)
    for marker in ("self._aida_multipage_patch = 4", "async def list_pages", "async def resolve_page", "page_id", "active_page_id", "_pending_page_ids_by_context", "page_privacy_verified", "def _mark_page_terminal", "AIDA_CAMOUFOX_FAST_VISIBLE_FALLBACK", "aida_camoufox_bridge_20260620_crash_diag_1", "aida_bridge_patch_active", "aida_launch_policy_resolved", "context_close_event", "cmdline_sha256", "subprocess_diagnostics_installed", "stdout_capture", "stderr_capture", "exit_ts_ms", "diagnostic_original_style_bundled", "_registered_page_records"):
        if marker not in text:
            fail(f"browser validation missing {marker}")
    validate_browser_addon_policy_contract(path, text)
    validate_browser_launch_budget_contract(path, text)
    validate_browser_context_viewport_contract(path, text)
    write_text(path, text)


def patch_navigation(path: pathlib.Path) -> None:
    text = read_text(path)
    text = patch_navigation_launch_params(path, text)
    if "async def list_pages(" in text and "page_id: str | None = None" in text:
        text = patch_navigation_reset_cleanup(path, text)
        text = patch_navigation_capture(path, text)
        text = patch_navigation_diagnostics(path, text)
        for marker in ("navigation_lifecycle_degraded", "first_failure_phase", "timeout_source", "_NavigationLifecycleError", "diagnose_bloxflip_matrix", "original_style_bundled", "node_exit_code", "camoufox_child_exits", "cloudflare"):
            if marker not in text:
                fail(f"navigation validation missing {marker}")
        if "navigate_wait_until_resolved" not in text:
            fail(f"navigation wait_until contract missing navigate_wait_until_resolved in {path}")
        if 'if primary_wait_until == "load":\n            primary_wait_until = "domcontentloaded"' in text:
            fail(f"navigation wait_until contract still downgrades load->domcontentloaded in {path}")
        write_text(path, text)
        return
    text = replace_once(
        text,
        "@mcp.tool()\nasync def close_browser() -> dict:\n    \"\"\"Close the Camoufox browser and release all resources.\"\"\"\n    try:\n        return await browser_manager.close()\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n",
        "@mcp.tool()\nasync def close_browser() -> dict:\n    \"\"\"Close the Camoufox browser and release all resources.\"\"\"\n    try:\n        return await browser_manager.close()\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n"
        "@mcp.tool()\nasync def list_pages() -> dict:\n    try:\n        pages = await browser_manager.list_pages()\n        return {\"session_id\": browser_manager.session_id, \"active_page_id\": browser_manager.active_page_id, \"page_count\": len(pages), \"pages\": pages}\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n"
        "@mcp.tool()\nasync def new_page(url: str | None = None, page_id: str | None = None, make_active: bool = True) -> dict:\n    try:\n        return await browser_manager.new_page(url=url, page_id=page_id, make_active=make_active)\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n"
        "@mcp.tool()\nasync def select_page(page_id: str) -> dict:\n    try:\n        return await browser_manager.select_page(page_id)\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n"
        "@mcp.tool()\nasync def close_page(page_id: str) -> dict:\n    try:\n        return await browser_manager.close_page(page_id)\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n",
        "navigation page tool insertion",
    )
    text = text.replace(
        "async def navigate(\n"
        "    url: str,\n",
        "async def navigate(\n"
        "    url: str,\n"
        "    page_id: str | None = None,\n",
    )
    text = text.replace("        page = await browser_manager.get_active_page()\n", "        page = await browser_manager.resolve_page(page_id)\n")
    text = text.replace("            browser_manager.reset_nav_responses()\n", "            browser_manager.reset_nav_responses(page_id)\n")
    text = text.replace("            chain = list(browser_manager._nav_responses)\n", "            chain = browser_manager.nav_responses_for_page(page_id)\n")
    text = replace_once(
        text,
        "        if title_error:\n            out[\"title_error\"] = title_error\n        return out\n\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\nasync def _inject_hook_by_name",
        "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\nasync def _inject_hook_by_name",
        "navigation navigate envelope",
    )
    text = text.replace("async def reload(wait_until: str = \"load\") -> dict:", "async def reload(wait_until: str = \"load\", page_id: str | None = None) -> dict:")
    reload_old = "        if title_error:\n            out[\"title_error\"] = title_error\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot"
    reload_new = "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot"
    reload_raw = "        await page.goto(current_url, wait_until=wait_until)\n        return {\"url\": page.url, \"title\": await page.title()}\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot"
    reload_raw_new = "        await page.goto(current_url, wait_until=wait_until)\n        title = \"\"\n        title_error = None\n        try:\n            title = await page.title()\n        except Exception as e:\n            title_error = str(e)\n        out = {\"url\": page.url, \"title\": title}\n        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot"
    if reload_old in text:
        text = text.replace(reload_old, reload_new, 1)
    elif reload_raw in text:
        text = text.replace(reload_raw, reload_raw_new, 1)
    elif "out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def take_screenshot" not in text:
        fail(f"navigation reload envelope anchor missing {path}")
    text = text.replace("async def take_screenshot(full_page: bool = False, selector: str | None = None) -> dict:", "async def take_screenshot(full_page: bool = False, selector: str | None = None, page_id: str | None = None) -> dict:")
    text = replace_once(
        text,
        "        return {\"screenshot_base64\": base64.b64encode(data).decode(), \"format\": \"png\"}\n",
        "        out = {\"screenshot_base64\": base64.b64encode(data).decode(), \"format\": \"png\"}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
        "navigation screenshot envelope",
    )
    text = text.replace("async def take_snapshot() -> dict:", "async def take_snapshot(page_id: str | None = None) -> dict:")
    text = replace_once(
        text,
        "        return {\"snapshot\": snapshot}\n",
        "        out = {\"snapshot\": snapshot}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
        "navigation snapshot envelope",
    )
    text = text.replace("async def click(selector: str) -> dict:", "async def click(selector: str, page_id: str | None = None) -> dict:")
    text = replace_once(
        text,
        "        await page.click(selector)\n        return {\"status\": \"clicked\", \"selector\": selector}\n",
        "        await page.click(selector)\n        out = {\"status\": \"clicked\", \"selector\": selector}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
        "navigation click envelope",
    )
    text = text.replace("async def type_text(selector: str, text: str, delay: int = 50) -> dict:", "async def type_text(selector: str, text: str, delay: int = 50, page_id: str | None = None) -> dict:")
    text = replace_once(
        text,
        "        await page.type(selector, text, delay=delay)\n        return {\"status\": \"typed\", \"selector\": selector, \"text\": text}\n",
        "        await page.type(selector, text, delay=delay)\n        out = {\"status\": \"typed\", \"selector\": selector, \"text\": text}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
        "navigation type envelope",
    )
    text = text.replace(
        "async def wait_for(\n    selector: str | None = None,\n    url_pattern: str | None = None,\n    timeout: int = 30000,\n) -> dict:",
        "async def wait_for(\n    selector: str | None = None,\n    url_pattern: str | None = None,\n    timeout: int = 30000,\n    page_id: str | None = None,\n) -> dict:",
    )
    text = replace_once(
        text,
        "            await page.wait_for_selector(selector, timeout=timeout)\n            return {\"status\": \"found\", \"selector\": selector}\n",
        "            await page.wait_for_selector(selector, timeout=timeout)\n            out = {\"status\": \"found\", \"selector\": selector}\n            out.update(await browser_manager.page_envelope(page))\n            return out\n",
        "navigation wait selector envelope",
    )
    text = replace_once(
        text,
        "            await page.wait_for_url(url_pattern, timeout=timeout)\n            return {\"status\": \"matched\", \"url_pattern\": url_pattern}\n",
        "            await page.wait_for_url(url_pattern, timeout=timeout)\n            out = {\"status\": \"matched\", \"url_pattern\": url_pattern}\n            out.update(await browser_manager.page_envelope(page))\n            return out\n",
        "navigation wait url envelope",
    )
    text = text.replace("async def get_page_info() -> dict:", "async def get_page_info(page_id: str | None = None) -> dict:")
    page_info_old = "        if title_error:\n            out[\"title_error\"] = title_error\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state"
    page_info_new = "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state"
    page_info_raw = "        bounds = await browser_manager._page_bounds(page)\n        return {\n            \"url\": page.url, \"title\": await page.title(),\n            \"viewport_width\": viewport.get(\"width\"),\n            \"viewport_height\": viewport.get(\"height\"),\n            \"window_bounds\": bounds,\n        }\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state"
    page_info_raw_new = "        bounds = await browser_manager._page_bounds(page)\n        title = \"\"\n        title_error = None\n        try:\n            title = await page.title()\n        except Exception as e:\n            title_error = str(e)\n        out = {\n            \"url\": page.url, \"title\": title,\n            \"viewport_width\": viewport.get(\"width\"),\n            \"viewport_height\": viewport.get(\"height\"),\n            \"window_bounds\": bounds,\n        }\n        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state"
    if page_info_old in text:
        text = text.replace(page_info_old, page_info_new, 1)
    elif page_info_raw in text:
        text = text.replace(page_info_raw, page_info_raw_new, 1)
    elif "out.update(await browser_manager.page_envelope(page))\n        return out\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\n@mcp.tool()\nasync def reset_browser_state" not in text:
        fail(f"navigation page info envelope anchor missing {path}")
    if "async def list_pages(" not in text or "page_id: str | None = None" not in text:
        fail(f"navigation validation failed {path}")
    text = patch_navigation_reset_cleanup(path, text)
    text = patch_navigation_capture(path, text)
    text = patch_navigation_diagnostics(path, text)
    write_text(path, text)


def patch_debugging(path: pathlib.Path) -> None:
    text = read_text(path)
    if "timeout_ms: int = 30000" in text and "_eval_with_budget" in text and "browser_manager.resolve_page(page_id)" in text:
        write_text(path, text)
        return
    if "playwright_evaluate_signature" not in text:
        text = replace_once(
            text,
            "    # Timeout\n    elif \"timeout\" in error_msg.lower() or \"exceeded\" in error_msg.lower():\n",
            "    elif \"takes exactly\" in error_msg.lower() and \"argument\" in error_msg.lower():\n"
            "        hint = (\n"
            "            \"The JavaScript expression or browser callback was invoked with the wrong arity. \"\n"
            "            \"evaluate_js expects expression, await_promise, and optional page_id; \"\n"
            "            \"inspect the target function's name and length before calling it, or call it with all required parameters inside an IIFE.\"\n"
            "        )\n"
            "    # Timeout\n    elif \"timeout\" in error_msg.lower() or \"exceeded\" in error_msg.lower():\n",
            "debugging arity hint",
        )
        text = replace_once(
            text,
            "    return {\n"
            "        \"type\": \"error\",\n"
            "        \"error\": error_msg,\n"
            "        \"hint\": hint,\n"
            "    }\n",
            "    return {\n"
            "        \"type\": \"error\",\n"
            "        \"error\": error_msg,\n"
            "        \"hint\": hint,\n"
            "        \"playwright_evaluate_signature\": \"page.evaluate(expression, arg?)\",\n"
            "        \"mcp_arguments\": [\"expression\", \"await_promise\", \"page_id\"],\n"
            "    }\n",
            "debugging error signature metadata",
        )
    if "async def evaluate_js(expression: str, await_promise: bool = True, page_id: str | None = None)" not in text:
        text = replace_once(
            text,
            "async def evaluate_js(expression: str, await_promise: bool = True) -> dict:",
            "async def evaluate_js(expression: str, await_promise: bool = True, page_id: str | None = None) -> dict:",
            "debugging evaluate signature",
        )
        text = replace_once(text, "        page = await browser_manager.get_active_page()\n", "        page = await browser_manager.resolve_page(page_id)\n", "debugging page resolve")
        text = replace_once(
            text,
            "        if isinstance(raw, dict) and \"error\" in raw:\n",
            "        envelope = await browser_manager.page_envelope(page)\n\n        if isinstance(raw, dict) and \"error\" in raw:\n",
            "debugging envelope local",
        )
    if "                    **(await browser_manager.page_envelope(page)),\n" not in text:
        text = re.sub(
            r'(\n[ \t]+"warnings": \[f"direct evaluate failed, used handle fallback: \{msg\[:200\]\}"\],\n)([ \t]+)\}',
            r'\1\2**(await browser_manager.page_envelope(page)),\n\2}',
            text,
            count=1,
        )
    text = text.replace(
        "                    \"warnings\": [\n                        f\"Expression returned a Symbol ({symbol_desc}). \"\n                        \"Symbols are not JSON-serializable; value is None.\"\n                    ],\n                }\n",
        "                    \"warnings\": [\n                        f\"Expression returned a Symbol ({symbol_desc}). \"\n                        \"Symbols are not JSON-serializable; value is None.\"\n                    ],\n                    **envelope,\n                }\n",
    )
    text = text.replace(
        "                    \"warnings\": [\n                        \"Expression returned undefined. If unintended, \"\n                        \"wrap logic in IIFE with explicit return: \"\n                        \"(() => { /* logic */; return <your_value>; })()\"\n                    ],\n                }\n",
        "                    \"warnings\": [\n                        \"Expression returned undefined. If unintended, \"\n                        \"wrap logic in IIFE with explicit return: \"\n                        \"(() => { /* logic */; return <your_value>; })()\"\n                    ],\n                    **envelope,\n                }\n",
    )
    text = text.replace(
        "                \"warnings\": None,\n            }\n",
        "                \"warnings\": None,\n                **envelope,\n            }\n",
        1,
    )
    text = text.replace(
        "                    \"warnings\": warnings_list if warnings_list else None,\n                }\n",
        "                    \"warnings\": warnings_list if warnings_list else None,\n                    **envelope,\n                }\n",
        1,
    )
    text = text.replace(
        "                \"warnings\": warnings_list if warnings_list else None,\n            }\n",
        "                \"warnings\": warnings_list if warnings_list else None,\n                **envelope,\n            }\n",
        1,
    )
    text = text.replace(
        "            \"warnings\": warnings_list if warnings_list else None,\n        }\n",
        "            \"warnings\": warnings_list if warnings_list else None,\n            **envelope,\n        }\n",
        1,
    )
    if "page_id: str | None = None" not in text or "browser_manager.resolve_page(page_id)" not in text:
        fail(f"debugging validation failed {path}")
    write_text(path, text)


def patch_jsvmp_hooking_diagnostics(path: pathlib.Path, text: str) -> str:
    if "async def hook_jsvmp_interpreter(" not in text or "jsvmp_phase_begin" in text:
        return text
    if "import time\n" not in text:
        insert_pos = 0
        for match in re.finditer(r"from __future__ import [^\n]+\n", text):
            if match.start() == insert_pos:
                insert_pos = match.end()
            else:
                break
        text = text[:insert_pos] + "import time\n" + text[insert_pos:]
    if "from ..browser import _camoufox_debug" not in text:
        text = replace_once(
            text,
            "from ..server import mcp, browser_manager\n",
            "from ..server import mcp, browser_manager\nfrom ..browser import _camoufox_debug, _safe_text\n",
            "jsvmp debug import",
        )
    elif "from ..browser import _camoufox_debug, _safe_text" not in text and "from ..browser import _safe_text, _camoufox_debug" not in text:
        text = text.replace("from ..browser import _camoufox_debug\n", "from ..browser import _camoufox_debug, _safe_text\n", 1)
    start = text.find("async def hook_jsvmp_interpreter(")
    next_tool = text.find("\n\n@mcp.tool()", start + 1)
    if next_tool < 0:
        next_tool = len(text)
    block = text[start:next_tool]
    sig_end = block.find(":\n")
    if sig_end < 0:
        fail(f"jsvmp signature validation failed {path}")
    block = block[:sig_end + 2] + (
        "    jsvmp_started = time.perf_counter()\n"
        "    _camoufox_debug(\"jsvmp_phase_begin\", phase=\"entry\", page_id=str(locals().get(\"page_id\") or \"\"), target=str(locals().get(\"function_path\") or locals().get(\"target\") or locals().get(\"pattern\") or \"\"))\n"
    ) + block[sig_end + 2:]
    if "page = await browser_manager.get_active_page()" in block:
        block = block.replace(
            "        page = await browser_manager.get_active_page()\n",
            "        _camoufox_debug(\"jsvmp_phase_begin\", phase=\"resolve_page\", elapsed_ms=int((time.perf_counter() - jsvmp_started) * 1000), page_id=str(locals().get(\"page_id\") or \"\"))\n"
            "        page = await browser_manager.get_active_page()\n"
            "        _camoufox_debug(\"jsvmp_phase_ok\", phase=\"resolve_page\", elapsed_ms=int((time.perf_counter() - jsvmp_started) * 1000), active_page_id=getattr(browser_manager, \"active_page_id\", None), page_count=len(getattr(browser_manager, \"pages\", {}) or {}))\n",
            1,
        )
    elif "page = await browser_manager.resolve_page(page_id)" in block:
        block = block.replace(
            "        page = await browser_manager.resolve_page(page_id)\n",
            "        _camoufox_debug(\"jsvmp_phase_begin\", phase=\"resolve_page\", elapsed_ms=int((time.perf_counter() - jsvmp_started) * 1000), page_id=str(locals().get(\"page_id\") or \"\"))\n"
            "        page = await browser_manager.resolve_page(page_id)\n"
            "        _camoufox_debug(\"jsvmp_phase_ok\", phase=\"resolve_page\", elapsed_ms=int((time.perf_counter() - jsvmp_started) * 1000), active_page_id=getattr(browser_manager, \"active_page_id\", None), page_count=len(getattr(browser_manager, \"pages\", {}) or {}))\n",
            1,
        )
    block = block.replace(
        "        await page.add_init_script",
        "        _camoufox_debug(\"jsvmp_phase_begin\", phase=\"add_init_script\", elapsed_ms=int((time.perf_counter() - jsvmp_started) * 1000), active_page_id=getattr(browser_manager, \"active_page_id\", None))\n        await page.add_init_script",
        1,
    )
    block = block.replace(
        "        await page.evaluate",
        "        _camoufox_debug(\"jsvmp_phase_begin\", phase=\"evaluate_probe\", elapsed_ms=int((time.perf_counter() - jsvmp_started) * 1000), active_page_id=getattr(browser_manager, \"active_page_id\", None))\n        await page.evaluate",
        1,
    )
    block = block.replace(
        "        return {",
        "        _camoufox_debug(\"jsvmp_phase_ok\", phase=\"return\", elapsed_ms=int((time.perf_counter() - jsvmp_started) * 1000), active_page_id=getattr(browser_manager, \"active_page_id\", None), page_count=len(getattr(browser_manager, \"pages\", {}) or {}))\n        return {",
    )
    block = block.replace(
        "    except Exception as e:\n        return {\"error\": str(e)}\n",
        "    except Exception as e:\n        _camoufox_debug(\"jsvmp_phase_exception\", phase=\"exception\", elapsed_ms=int((time.perf_counter() - jsvmp_started) * 1000), error_type=type(e).__name__, error_summary=_safe_text(e, 800), active_page_id=getattr(browser_manager, \"active_page_id\", None), page_count=len(getattr(browser_manager, \"pages\", {}) or {}))\n        return {\"error\": str(e), \"status\": \"error\", \"phase\": \"jsvmp_exception\", \"error_type\": type(e).__name__}\n",
        1,
    )
    for marker in ("jsvmp_phase_begin", "jsvmp_phase_ok", "_camoufox_debug"):
        if marker not in block:
            fail(f"jsvmp diagnostics validation missing {marker} in {path}")
    return text[:start] + block + text[next_tool:]


def patch_network(path: pathlib.Path) -> None:
    text = read_text(path)
    if (
        "_aida_network_hook_counts" in text
        and "browser_network_initiator_unknown_source" in text
        and AIDA_INITIATOR_CONTRACT_V2 in text
        and "_NETWORK_DEFAULT_LIMIT" in text
        and "url_prefix: str | None = None" in text
        and '"filtered_count"' in text
        and '"has_more"' in text
        and "include_body: bool = False" in text
        and "body_tasks = []" in text
        and "response_body_available" in text
    ):
        return
    if "import asyncio\n" not in text:
        if "from __future__ import annotations\n\n" in text:
            text = text.replace("from __future__ import annotations\n\n", "from __future__ import annotations\n\nimport asyncio\n", 1)
        else:
            text = "import asyncio\n" + text
    if "AIDA_INITIATOR_CONTRACT_V2" not in text:
        insert_pos = 0
        for match in re.finditer(r"(?:from __future__ import [^\n]+\n|import [^\n]+\n|from [^\n]+ import [^\n]+\n)", text):
            if match.start() == insert_pos:
                insert_pos = match.end()
            else:
                break
        text = text[:insert_pos] + f"AIDA_INITIATOR_CONTRACT_V2 = \"{AIDA_INITIATOR_CONTRACT_V2}\"\n" + text[insert_pos:]
    if "from ..browser import _camoufox_debug" not in text:
        text = replace_once(
            text,
            "from ..server import mcp, browser_manager\n",
            "from ..server import mcp, browser_manager\nfrom ..browser import _camoufox_debug, _safe_text\n",
            "network debug import",
        )
    if "async def _aida_network_hook_counts" not in text:
        helper = '''async def _aida_network_hook_counts(page=None, marker: str | None = None, clear: bool = False) -> dict:
    marker_text = str(marker or "")
    out: dict = {"marker": marker_text, "clear": bool(clear), "available": False}
    if page is None:
        out["error"] = "no_page"
        return out
    try:
        result = await page.evaluate("""([marker, clear]) => {
            const names = ["__mcp_xhr_log", "__mcp_fetch_log", "__mcp_fetch_initiator_log"];
            const before = {};
            const after = {};
            for (const name of names) {
                const value = Array.isArray(window[name]) ? window[name] : [];
                before[name] = value.length;
                if (clear) window[name] = [];
                after[name] = Array.isArray(window[name]) ? window[name].length : 0;
            }
            return {
                available: true,
                marker: marker || "",
                clear: !!clear,
                xhr_hook_active: !!window.__mcp_xhr_hooked,
                fetch_hook_active: !!window.__mcp_fetch_hooked,
                xhr_log_count: before.__mcp_xhr_log || 0,
                fetch_log_count: before.__mcp_fetch_log || 0,
                fetch_initiator_log_count: before.__mcp_fetch_initiator_log || 0,
                before,
                after,
            };
        }""", [marker_text, bool(clear)])
        if isinstance(result, dict):
            out.update(result)
        return out
    except Exception as exc:
        out["error_type"] = type(exc).__name__
        out["error"] = _safe_text(exc, 500)
        return out


'''
        text = replace_once(text, "\n\n@mcp.tool()\nasync def network_capture", "\n\n" + helper + "@mcp.tool()\nasync def network_capture", "network hook count helper")
    if "    page_id: str | None = None,\n    marker: str | None = None,\n" not in text:
        text = replace_once(
            text,
            "async def network_capture(\n"
            "    action: str,\n"
            "    url_pattern: str = \"**/*\",\n"
            "    capture_body: bool = False,\n"
            ") -> dict:\n",
            "async def network_capture(\n"
            "    action: str,\n"
            "    url_pattern: str = \"**/*\",\n"
            "    capture_body: bool = False,\n"
            "    page_id: str | None = None,\n"
            "    marker: str | None = None,\n"
            ") -> dict:\n",
            "network capture signature",
        )
    if "hook_counts = await _aida_network_hook_counts" not in text:
        text = replace_once(
            text,
            "    if action == \"start\":\n"
            "        browser_manager._capturing = True\n",
            "    hook_page = None\n"
            "    hook_counts = {}\n"
            "    if action in (\"start\", \"clear\", \"status\"):\n"
            "        try:\n"
            "            hook_page = await browser_manager.resolve_page(page_id)\n"
            "        except Exception as exc:\n"
            "            hook_counts = {\"error_type\": type(exc).__name__, \"error\": _safe_text(exc, 500), \"marker\": str(marker or \"\")}\n"
            "    if action in (\"start\", \"clear\") and hook_page is not None:\n"
            "        hook_counts = await _aida_network_hook_counts(hook_page, marker, True)\n"
            "        _camoufox_debug(\"network_capture_hook_clear\", action=action, page_id=page_id or getattr(browser_manager, \"active_page_id\", \"\") or \"\", marker=str(marker or \"\"), hook_counts=hook_counts)\n"
            "    elif action == \"status\" and hook_page is not None:\n"
            "        hook_counts = await _aida_network_hook_counts(hook_page, marker, False)\n"
            "    if action == \"start\":\n"
            "        browser_manager._capturing = True\n",
            "network capture hook clear",
        )
    text = text.replace(
        "        return {\"status\": \"capturing\", \"pattern\": url_pattern,\n"
        "                \"capture_body\": capture_body}\n",
        "        return {\"status\": \"capturing\", \"pattern\": url_pattern,\n"
        "                \"capture_body\": capture_body, \"page_id\": page_id, \"active_page_id\": getattr(browser_manager, \"active_page_id\", None), \"marker\": str(marker or \"\"), \"hook_counts\": hook_counts}\n",
    )
    text = text.replace(
        "        return {\"status\": \"stopped\",\n"
        "                \"total_requests\": len(browser_manager._network_requests)}\n",
        "        return {\"status\": \"stopped\",\n"
        "                \"total_requests\": len(browser_manager._network_requests), \"page_id\": page_id, \"active_page_id\": getattr(browser_manager, \"active_page_id\", None), \"marker\": str(marker or \"\")}\n",
    )
    text = text.replace(
        "        return {\"status\": \"cleared\", \"cleared_count\": count}\n",
        "        return {\"status\": \"cleared\", \"cleared_count\": count, \"page_id\": page_id, \"active_page_id\": getattr(browser_manager, \"active_page_id\", None), \"marker\": str(marker or \"\"), \"hook_counts\": hook_counts}\n",
    )
    text = text.replace(
        "            \"buffer_size\": len(browser_manager._network_requests),\n"
        "        }\n",
        "            \"buffer_size\": len(browser_manager._network_requests),\n"
        "            \"page_id\": page_id,\n"
        "            \"active_page_id\": getattr(browser_manager, \"active_page_id\", None),\n"
        "            \"marker\": str(marker or \"\"),\n"
        "            \"hook_counts\": hook_counts,\n"
        "        }\n",
        1,
    )
    if "async def list_network_requests(\n    page_id: str | None = None,\n" not in text:
        text = replace_once(
            text,
            "async def list_network_requests(\n"
            "    url_filter: str | None = None,\n",
            "async def list_network_requests(\n"
            "    page_id: str | None = None,\n"
            "    url_filter: str | None = None,\n",
            "network list signature",
        )
    if "url_prefix: str | None = None" not in text:
        text = replace_once(
            text,
            "    url_filter: str | None = None,\n",
            "    url_filter: str | None = None,\n"
            "    url_prefix: str | None = None,\n",
            "network url prefix signature",
        )
    if "if page_id:\n            reqs = [r for r in reqs if r.get(\"page_id\") == page_id]" not in text:
        text = replace_once(
            text,
            "        if url_filter:\n",
            "        if page_id:\n            reqs = [r for r in reqs if r.get(\"page_id\") == page_id]\n        if url_filter:\n",
            "network page filter",
        )
    if "if url_prefix:\n            reqs = [r for r in reqs if str(r.get(\"url\") or \"\").startswith(url_prefix)]" not in text:
        text = replace_once(
            text,
            "        if url_filter:\n            reqs = [r for r in reqs if url_filter in r.get(\"url\", \"\")]\n",
            "        if url_filter:\n            reqs = [r for r in reqs if url_filter in r.get(\"url\", \"\")]\n"
            "        if url_prefix:\n            reqs = [r for r in reqs if str(r.get(\"url\") or \"\").startswith(url_prefix)]\n",
            "network url prefix filter",
        )
    if "\"url_prefix\": str(url_prefix or \"\")" not in text:
        text = replace_once(
            text,
            "            \"filter\": str(filter or \"\"),\n",
            "            \"filter\": str(filter or \"\"),\n"
            "            \"url_prefix\": str(url_prefix or \"\"),\n",
            "network url prefix envelope",
        )
    if "include_body: bool = False" not in text:
        text = replace_in_function(
            text,
            "list_network_requests",
            "    include_initiator_snapshots: bool = True,\n) -> dict:\n",
            "    include_initiator_snapshots: bool = True,\n    include_body: bool = False,\n    max_body_size: int = 5000,\n) -> dict:\n",
            "network list body signature",
        )
    if "body_tasks = []" not in text:
        text = replace_in_function(
            text,
            "list_network_requests",
            "        paged_reqs = reqs[safe_offset:safe_offset + safe_limit] if safe_limit > 0 else []\n\n"
            "        effective_marker = str(marker or filter or url_filter or url_prefix or \"\")\n",
            "        paged_reqs = reqs[safe_offset:safe_offset + safe_limit] if safe_limit > 0 else []\n"
            "        if include_body:\n"
            "            body_tasks = []\n"
            "            for r in paged_reqs:\n"
            "                task = r.get(\"response_body_task\")\n"
            "                if isinstance(task, asyncio.Future) and not task.done():\n"
            "                    body_tasks.append(task)\n"
            "            if body_tasks:\n"
            "                await asyncio.wait(body_tasks, timeout=2.0)\n\n"
            "        effective_marker = str(marker or filter or url_filter or url_prefix or \"\")\n",
            "network list body wait",
        )
    if "request_body = r.get(\"request_body\") or r.get(\"request_post_data\") or r.get(\"post_data\") or \"\"" not in text:
        text = replace_in_function(
            text,
            "list_network_requests",
            "            request_body_length = int(r.get(\"request_body_length\") or len(r.get(\"request_post_data\") or r.get(\"post_data\") or \"\"))\n"
            "            summaries.append({\n",
            "            request_body = r.get(\"request_body\") or r.get(\"request_post_data\") or r.get(\"post_data\") or \"\"\n"
            "            request_body_length = int(r.get(\"request_body_length\") or len(request_body or \"\"))\n"
            "            summary = {\n",
            "network list body summary begin",
        )
        text = replace_in_function(
            text,
            "list_network_requests",
            "                \"initiator_source\": _initiator_snapshot_source(snapshot),\n"
            "                \"initiator_stack_len\": len(str(snapshot.get(\"stack\") or \"\")),\n"
            "            })\n",
            "                \"initiator_source\": _initiator_snapshot_source(snapshot),\n"
            "                \"initiator_stack_len\": len(str(snapshot.get(\"stack\") or \"\")),\n"
            "                \"response_body_available\": r.get(\"response_body\") is not None,\n"
            "            }\n"
            "            if include_body:\n"
            "                response_body = r.get(\"response_body\")\n"
            "                bounded_body_size = _bounded_int(max_body_size, 5000, -1, 10_000_000)\n"
            "                if request_body:\n"
            "                    summary[\"request_body\"] = request_body\n"
            "                    summary[\"post_data\"] = request_body\n"
            "                if response_body is not None:\n"
            "                    if bounded_body_size >= 0 and len(response_body) > bounded_body_size:\n"
            "                        summary[\"response_body\"] = response_body[:bounded_body_size]\n"
            "                        summary[\"response_body_truncated\"] = True\n"
            "                        summary[\"response_body_original_size\"] = len(response_body)\n"
            "                        summary[\"response_body_size_returned\"] = bounded_body_size\n"
            "                    else:\n"
            "                        summary[\"response_body\"] = response_body\n"
            "                        summary[\"response_body_truncated\"] = False\n"
            "                        summary[\"response_body_original_size\"] = len(response_body)\n"
            "                        summary[\"response_body_size_returned\"] = len(response_body)\n"
            "            summaries.append(summary)\n",
            "network list body summary finish",
        )
    if "result.pop(\"response_body_task\", None)" not in text:
        text = replace_in_function(
            text,
            "get_network_request",
            "                result = dict(r)\n"
            "                if not include_body:\n",
            "                result = dict(r)\n"
            "                result.pop(\"response_body_task\", None)\n"
            "                if not include_body:\n",
            "network get strip body task",
        )
    if "\"page_id\": r.get(\"page_id\")" not in text:
        text = replace_once(
            text,
            "                \"id\": r[\"id\"], \"url\": r[\"url\"][:200], \"method\": r[\"method\"],\n"
            "                \"status\": r.get(\"status\"), \"type\": r.get(\"resource_type\"),\n",
            "                \"id\": r[\"id\"], \"page_id\": r.get(\"page_id\"), \"context_id\": r.get(\"context_id\"),\n"
            "                \"url\": r[\"url\"][:200], \"method\": r[\"method\"],\n"
            "                \"status\": r.get(\"status\"), \"type\": r.get(\"resource_type\"),\n",
            "network summary page fields",
        )
    if "\"page_count\": len(browser_manager.pages)" not in text:
        text = replace_once(
            text,
            "            \"count\": len(summaries),\n"
            "            \"capturing\": browser_manager._capturing,\n",
            "            \"count\": len(summaries),\n"
            "            \"page_id\": page_id,\n"
            "            \"active_page_id\": browser_manager.active_page_id,\n"
            "            \"page_count\": len(browser_manager.pages),\n"
            "            \"capturing\": browser_manager._capturing,\n",
            "network list envelope",
        )
    if "async def get_request_initiator(request_id: int) -> dict:" in text and "browser_network_initiator_request_not_found" not in text:
        legacy_block = '''@mcp.tool()
async def get_request_initiator(request_id: int, page_id: str | None = None, marker: str | None = None) -> dict:
    started = time.perf_counter()
    request_marker = str(marker or "")
    try:
        target_entry = None
        id_match = None
        for entry in browser_manager._network_requests:
            if entry.get("id") == request_id:
                if id_match is None:
                    id_match = entry
                if not page_id or entry.get("page_id") == page_id:
                    target_entry = entry
                    break
        if target_entry is None:
            requested_page_id = page_id or (id_match.get("page_id") if isinstance(id_match, dict) else None)
            return {
                "initiator_contract": AIDA_INITIATOR_CONTRACT_V2,
                "success": False,
                "status": "failed",
                "error": "browser_network_initiator_request_not_found",
                "request_id": request_id,
                "request_page_id": requested_page_id,
                "resolved_page_id": requested_page_id,
                "active_page_id": getattr(browser_manager, "active_page_id", None),
                "request_marker": request_marker,
                "hook_counts_before": {},
                "hook_counts_after": {},
                "fetch_initiator_log_count": 0,
                "diagnostics": {
                    "requested_page_id": page_id,
                    "marker": request_marker,
                    "id_match_page_id": id_match.get("page_id") if isinstance(id_match, dict) else None,
                    "buffer_size": len(browser_manager._network_requests),
                },
            }

        req_url = target_entry.get("url", "")
        target_page_id = str(page_id or target_entry.get("page_id") or "")
        try:
            page = await browser_manager.resolve_page(target_page_id or None)
        except Exception:
            page = await browser_manager.get_active_page()
        resolved_page_id = browser_manager.page_id_for(page) if hasattr(browser_manager, "page_id_for") else target_page_id
        hook_counts_before = await _aida_network_hook_counts(page, request_marker, False)
        escaped_url = json.dumps(req_url)
        escaped_marker = json.dumps(request_marker)
        result = await page.evaluate(f"""() => {{
            const reqUrl = {escaped_url};
            const marker = {escaped_marker};
            function markerMatches(logUrl, log) {{
                if (!marker) return true;
                const haystacks = [logUrl || '', log && log.url || '', log && log.marker || '', log && log.body || ''];
                return haystacks.some(v => String(v || '').includes(marker));
            }}
            function logCounts() {{
                const xhrLog = Array.isArray(window.__mcp_xhr_log) ? window.__mcp_xhr_log : [];
                const fetchLog = Array.isArray(window.__mcp_fetch_log) ? window.__mcp_fetch_log : [];
                const fetchInitLog = Array.isArray(window.__mcp_fetch_initiator_log) ? window.__mcp_fetch_initiator_log : [];
                return {{ xhr_log_count: xhrLog.length, fetch_log_count: fetchLog.length, fetch_initiator_log_count: fetchInitLog.length }};
            }}
            function matchUrl(logUrl) {{
                try {{
                    if (marker && !String(logUrl || '').includes(marker) && !String(reqUrl || '').includes(marker)) return false;
                    if (reqUrl === logUrl || String(reqUrl || '').includes(logUrl) || String(logUrl || '').includes(reqUrl)) return true;
                    const u1 = new URL(reqUrl, location.origin);
                    const u2 = new URL(logUrl, location.origin);
                    return u1.pathname === u2.pathname && u1.host === u2.host;
                }} catch(e) {{
                    return false;
                }}
            }}
            const fetchInitLog = Array.isArray(window.__mcp_fetch_initiator_log) ? window.__mcp_fetch_initiator_log : [];
            for (let i = fetchInitLog.length - 1; i >= 0; --i) {{
                const entry = fetchInitLog[i] || {{}};
                const logUrl = entry.url || '';
                if (markerMatches(logUrl, entry) && matchUrl(logUrl)) {{
                    return {{ url: logUrl, stack: entry.stack || null, type: entry.type || 'fetch_hook', method: entry.method, headers: entry.headers, body: entry.body, diagnostics: {{ counts: logCounts(), matched_log: 'fetch_initiator' }} }};
                }}
            }}
            const fetchLog = Array.isArray(window.__mcp_fetch_log) ? window.__mcp_fetch_log : [];
            for (let i = fetchLog.length - 1; i >= 0; --i) {{
                const entry = fetchLog[i] || {{}};
                const logUrl = entry.url || '';
                if (markerMatches(logUrl, entry) && matchUrl(logUrl)) {{
                    return {{ url: logUrl, stack: entry.stack || null, type: 'fetch_hook', method: entry.method, headers: entry.headers, body: entry.body, diagnostics: {{ counts: logCounts(), matched_log: 'fetch' }} }};
                }}
            }}
            const xhrLog = Array.isArray(window.__mcp_xhr_log) ? window.__mcp_xhr_log : [];
            for (let i = xhrLog.length - 1; i >= 0; --i) {{
                const entry = xhrLog[i] || {{}};
                const logUrl = entry.url || '';
                if (markerMatches(logUrl, entry) && matchUrl(logUrl)) {{
                    return {{ url: logUrl, stack: entry.stack || null, type: 'xhr_hook', method: entry.method, headers: entry.headers, body: entry.body, diagnostics: {{ counts: logCounts(), matched_log: 'xhr' }} }};
                }}
            }}
            return {{
                url: reqUrl,
                stack: null,
                type: 'unknown',
                diagnostics: {{
                    xhr_hook_active: !!window.__mcp_xhr_hooked,
                    fetch_hook_active: !!window.__mcp_fetch_hooked,
                    marker: marker || '',
                    counts: logCounts(),
                    hint: !window.__mcp_xhr_hooked && !window.__mcp_fetch_hooked
                        ? 'No hooks detected. Call inject_hook_preset before navigating.'
                        : 'Hooks active but no matching URL found in logs.'
                }}
            }};
        }}""")
        source = result.get("type", "unknown") if isinstance(result, dict) else "unknown"
        diagnostics = result.get("diagnostics") if isinstance(result, dict) and isinstance(result.get("diagnostics"), dict) else {}
        counts = diagnostics.get("counts") if isinstance(diagnostics.get("counts"), dict) else {}
        hook_counts_after = await _aida_network_hook_counts(page, request_marker, False)
        out = {
            "initiator_contract": AIDA_INITIATOR_CONTRACT_V2,
            "success": source not in ("unknown", None),
            "status": "ok" if source not in ("unknown", None) else "failed",
            "error": None if source not in ("unknown", None) else "browser_network_initiator_unknown_source",
            "request_id": request_id,
            "request_page_id": target_entry.get("page_id"),
            "resolved_page_id": resolved_page_id,
            "active_page_id": getattr(browser_manager, "active_page_id", None),
            "request_url": req_url,
            "request_marker": request_marker,
            "hook_counts_before": hook_counts_before,
            "hook_counts_after": hook_counts_after,
            "fetch_log_count": counts.get("fetch_log_count", hook_counts_after.get("fetch_log_count", 0)),
            "fetch_initiator_log_count": counts.get("fetch_initiator_log_count", hook_counts_after.get("fetch_initiator_log_count", 0)),
            "xhr_log_count": counts.get("xhr_log_count", hook_counts_after.get("xhr_log_count", 0)),
            "url": result.get("url") if isinstance(result, dict) else req_url,
            "initiator_stack": result.get("stack") if isinstance(result, dict) else None,
            "initiator_type": source,
            "source": source,
            "method": result.get("method") if isinstance(result, dict) else None,
            "request_headers": result.get("headers") if isinstance(result, dict) else None,
            "request_body": result.get("body") if isinstance(result, dict) else None,
            "diagnostics": diagnostics,
            "diagnostic": (
                {
                    "likely_causes": [
                        "hook registered after SDK",
                        "request made inside a sync-loaded SDK interceptor",
                        "fetch_hook.js not injected",
                    ],
                    "recommended_action": "Use reload_with_hooks() or inject hooks before navigate.",
                }
                if source in ("unknown", None) else None
            ),
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }
        if out["error"] is None:
            out.pop("error", None)
        return out
    except Exception as e:
        return {"success": False, "status": "failed", "error": "browser_network_initiator_exception", "error_type": type(e).__name__, "error_summary": _safe_text(e, 500), "initiator_contract": AIDA_INITIATOR_CONTRACT_V2, "request_id": request_id, "request_page_id": page_id, "resolved_page_id": page_id, "active_page_id": getattr(browser_manager, "active_page_id", None), "request_marker": str(marker or "")}
'''
        text, count = re.subn(
            r"@mcp\.tool\(\)\nasync def get_request_initiator\(request_id: int\) -> dict:\n.*?(?=\n\n@mcp\.tool\(\)\nasync def intercept_request)",
            legacy_block,
            text,
            count=1,
            flags=re.S,
        )
        if count != 1:
            fail(f"network legacy initiator replacement failed {path}")
    if "async def get_request_initiator(request_id: int, page_id: str | None = None, marker: str | None = None)" not in text:
        if "async def get_request_initiator(request_id: int, page_id: str | None = None) -> dict:" in text:
            text = text.replace(
                "async def get_request_initiator(request_id: int, page_id: str | None = None) -> dict:",
                "async def get_request_initiator(request_id: int, page_id: str | None = None, marker: str | None = None) -> dict:",
                1,
            )
        else:
            text = replace_once(
                text,
                "async def get_request_initiator(request_id: int) -> dict:",
                "async def get_request_initiator(request_id: int, page_id: str | None = None, marker: str | None = None) -> dict:",
                "network initiator signature",
            )
    if "if r[\"id\"] == request_id and (not page_id or r.get(\"page_id\") == page_id):" not in text:
        text = text.replace(
            "            if r[\"id\"] == request_id:\n",
            "            if r[\"id\"] == request_id and (not page_id or r.get(\"page_id\") == page_id):\n",
            1,
        )
    if "browser_network_initiator_request_not_found" not in text:
        text = replace_in_function(
            text,
            "get_request_initiator",
            "        if not target_entry:\n"
            "            return {\"error\": f\"Request {request_id} not found\"}\n",
            "        request_marker = str(marker or \"\")\n"
            "        if not target_entry:\n"
            "            return {\n"
            "                \"success\": False,\n"
            "                \"status\": \"failed\",\n"
            "                \"error\": \"browser_network_initiator_request_not_found\",\n"
            "                \"initiator_contract\": AIDA_INITIATOR_CONTRACT_V2,\n"
            "                \"request_id\": request_id,\n"
            "                \"request_page_id\": page_id,\n"
            "                \"resolved_page_id\": page_id,\n"
            "                \"active_page_id\": getattr(browser_manager, \"active_page_id\", None),\n"
            "                \"request_marker\": request_marker,\n"
            "                \"diagnostics\": {\"requested_page_id\": page_id, \"marker\": request_marker, \"buffer_size\": len(getattr(browser_manager, \"_network_requests\", []) or [])},\n"
            "            }\n",
            "network initiator not found contract",
        )
    if "page = await browser_manager.resolve_page(page_id or target_entry.get(\"page_id\"))" not in text:
        text = replace_once(
            text,
            "        page = await browser_manager.get_active_page()\n",
            "        page = await browser_manager.resolve_page(page_id or target_entry.get(\"page_id\"))\n",
            "network initiator resolve",
        )
    if "const marker = " not in text:
        text = replace_once(
            text,
            "        req_url = target_entry[\"url\"]\n"
            "        escaped_url = json.dumps(req_url)\n\n"
            "        result = await page.evaluate(f\"\"\"() => {{\n"
            "            const reqUrl = {escaped_url};\n",
            "        req_url = target_entry[\"url\"]\n"
            "        request_marker = str(marker or \"\")\n"
            "        escaped_url = json.dumps(req_url)\n"
            "        escaped_marker = json.dumps(request_marker)\n"
            "        hook_counts_before = await _aida_network_hook_counts(page, request_marker, False)\n\n"
            "        result = await page.evaluate(f\"\"\"() => {{\n"
            "            const reqUrl = {escaped_url};\n"
            "            const marker = {escaped_marker};\n"
            "            function markerMatches(logUrl, log) {{\n"
            "                if (!marker) return true;\n"
            "                const haystacks = [logUrl || '', log && log.url || '', log && log.marker || '', log && log.body || ''];\n"
            "                return haystacks.some(v => String(v || '').includes(marker));\n"
            "            }}\n"
            "            function logCounts() {{\n"
            "                const xhrLog = Array.isArray(window.__mcp_xhr_log) ? window.__mcp_xhr_log : [];\n"
            "                const fetchLog = Array.isArray(window.__mcp_fetch_log) ? window.__mcp_fetch_log : [];\n"
            "                const fetchInitLog = Array.isArray(window.__mcp_fetch_initiator_log) ? window.__mcp_fetch_initiator_log : [];\n"
            "                return {{ xhr_log_count: xhrLog.length, fetch_log_count: fetchLog.length, fetch_initiator_log_count: fetchInitLog.length }};\n"
            "            }}\n",
            "network initiator marker setup",
        )
    text = text.replace(
        "                    if (reqUrl === logUrl || reqUrl.includes(logUrl) || logUrl.includes(reqUrl)) {{\n",
        "                    if (markerMatches(logUrl, log) && (reqUrl === logUrl || reqUrl.includes(logUrl) || logUrl.includes(reqUrl))) {{\n",
    )
    text = text.replace(
        "                        if (u1.pathname === u2.pathname && u1.host === u2.host) {{\n",
        "                        if (markerMatches(logUrl, log) && u1.pathname === u2.pathname && u1.host === u2.host) {{\n",
    )
    text = text.replace(
        "                if (reqUrl === logUrl || reqUrl.includes(logUrl) || logUrl.includes(reqUrl)) {{\n",
        "                if (markerMatches(logUrl, entry) && (reqUrl === logUrl || reqUrl.includes(logUrl) || logUrl.includes(reqUrl))) {{\n",
    )
    text = text.replace(
        "                    if (markerMatches(logUrl, log) && u1.pathname === u2.pathname && u1.host === u2.host) {{\n"
        "                        return {{ url: logUrl, stack: entry.stack || null, type: 'fetch_hook',\n",
        "                    if (markerMatches(logUrl, entry) && u1.pathname === u2.pathname && u1.host === u2.host) {{\n"
        "                        return {{ url: logUrl, stack: entry.stack || null, type: 'fetch_hook',\n",
        1,
    )
    if "counts: logCounts()" not in text:
        text = replace_once(
            text,
            "                diagnostics: {{\n"
            "                    xhr_hook_active: !!window.__mcp_xhr_hooked,\n"
            "                    fetch_hook_active: !!window.__mcp_fetch_hooked,\n",
            "                diagnostics: {{\n"
            "                    xhr_hook_active: !!window.__mcp_xhr_hooked,\n"
            "                    fetch_hook_active: !!window.__mcp_fetch_hooked,\n"
            "                    marker: marker || '',\n"
            "                    counts: logCounts(),\n",
            "network initiator unknown counts",
        )
    if "diagnostics = result.get(\"diagnostics\") or {}" not in text and "\"initiator_contract\": AIDA_INITIATOR_CONTRACT_V2" not in text:
        text = replace_once(
            text,
            "        source = result.get(\"type\", \"unknown\")\n"
            "        return {\n"
            "            \"url\": result.get(\"url\"),\n",
            "        source = result.get(\"type\", \"unknown\")\n"
            "        diagnostics = result.get(\"diagnostics\") or {}\n"
            "        if isinstance(diagnostics.get(\"counts\"), dict):\n"
            "            counts = diagnostics.get(\"counts\")\n"
            "        else:\n"
            "            counts = {}\n"
            "        hook_counts_after = await _aida_network_hook_counts(page, request_marker, False)\n"
            "        resolved_page_id = browser_manager.page_id_for(page) if hasattr(browser_manager, \"page_id_for\") else (page_id or target_entry.get(\"page_id\"))\n"
            "        out = {\n"
            "            \"initiator_contract\": AIDA_INITIATOR_CONTRACT_V2,\n"
            "            \"success\": source not in (\"unknown\", None),\n"
            "            \"status\": \"ok\" if source not in (\"unknown\", None) else \"failed\",\n"
            "            \"error\": None if source not in (\"unknown\", None) else \"browser_network_initiator_unknown_source\",\n"
            "            \"request_id\": request_id,\n"
            "            \"request_page_id\": target_entry.get(\"page_id\"),\n"
            "            \"resolved_page_id\": resolved_page_id,\n"
            "            \"active_page_id\": getattr(browser_manager, \"active_page_id\", None),\n"
            "            \"request_url\": req_url,\n"
            "            \"request_marker\": request_marker,\n"
            "            \"fetch_log_count\": counts.get(\"fetch_log_count\", hook_counts_after.get(\"fetch_log_count\", 0)),\n"
            "            \"fetch_initiator_log_count\": counts.get(\"fetch_initiator_log_count\", hook_counts_after.get(\"fetch_initiator_log_count\", 0)),\n"
            "            \"xhr_log_count\": counts.get(\"xhr_log_count\", hook_counts_after.get(\"xhr_log_count\", 0)),\n"
            "            \"hook_counts_before\": hook_counts_before,\n"
            "            \"hook_counts_after\": hook_counts_after,\n"
            "            \"url\": result.get(\"url\"),\n",
            "network initiator result envelope",
        )
        text = replace_once(
            text,
            "            \"diagnostics\": result.get(\"diagnostics\"),\n"
            "            \"diagnostic\": (\n",
            "            \"diagnostics\": diagnostics,\n"
            "            \"diagnostic\": (\n",
            "network initiator diagnostics variable",
        )
    elif "\"initiator_contract\": AIDA_INITIATOR_CONTRACT_V2" not in text:
        text = replace_in_function(
            text,
            "get_request_initiator",
            "        out = {\n"
            "            \"success\": source not in (\"unknown\", None),\n",
            "        out = {\n"
            "            \"initiator_contract\": AIDA_INITIATOR_CONTRACT_V2,\n"
            "            \"success\": source not in (\"unknown\", None),\n",
            "network initiator contract field",
        )
    if "browser_network_initiator_exception" not in text:
        text = replace_in_function(
            text,
            "get_request_initiator",
            "    except Exception as e:\n"
            "        return {\"error\": str(e)}\n",
            "    except Exception as e:\n"
            "        return {\"success\": False, \"status\": \"failed\", \"error\": \"browser_network_initiator_exception\", \"error_type\": type(e).__name__, \"error_summary\": _safe_text(e, 500), \"initiator_contract\": AIDA_INITIATOR_CONTRACT_V2, \"request_id\": request_id, \"request_page_id\": page_id, \"resolved_page_id\": page_id, \"active_page_id\": getattr(browser_manager, \"active_page_id\", None), \"request_marker\": str(marker or \"\")}\n",
            "network initiator exception contract",
        )
        text = replace_once(
            text,
            "            ),\n"
            "        }\n"
            "    except Exception as e:\n",
            "            ),\n"
            "        }\n"
            "        if out[\"error\"] is None:\n"
            "            out.pop(\"error\", None)\n"
            "        return out\n"
            "    except Exception as e:\n",
            "network initiator return out",
        )
    if "\"diagnostics\": result.get(\"diagnostics\"),\n            **(await browser_manager.page_envelope(page)),\n" in text:
        text = text.replace(
            "\"diagnostics\": result.get(\"diagnostics\"),\n            **(await browser_manager.page_envelope(page)),\n",
            "\"diagnostics\": diagnostics,\n",
        )
    if "async def intercept_request(\n    url_pattern: str,\n    page_id: str | None = None," not in text:
        text = replace_once(
            text,
            "async def intercept_request(\n"
            "    url_pattern: str,\n",
            "async def intercept_request(\n"
            "    url_pattern: str,\n"
            "    page_id: str | None = None,\n",
            "network intercept signature",
        )
    if "page = await browser_manager.resolve_page(page_id)" not in text:
        text = replace_once(
            text,
            "        page = await browser_manager.get_active_page()\n",
            "        page = await browser_manager.resolve_page(page_id)\n",
            "network intercept resolve",
        )
    text = text.replace(
        "                return {\"status\": \"stopped\", \"pattern\": url_pattern}\n",
        "                out = {\"status\": \"stopped\", \"pattern\": url_pattern}\n                out.update(await browser_manager.page_envelope(page))\n                return out\n",
        1,
    )
    text = text.replace(
        "        return {\"status\": \"intercepting\", \"pattern\": url_pattern, \"action\": action}\n",
        "        out = {\"status\": \"intercepting\", \"pattern\": url_pattern, \"action\": action}\n        out.update(await browser_manager.page_envelope(page))\n        return out\n",
    )
    if "\"page_id\": r.get(\"page_id\")" not in text or "browser_manager.resolve_page(page_id" not in text:
        fail(f"network validation failed {path}")
    for marker in ("_aida_network_hook_counts", "request_marker", "fetch_initiator_log_count", "browser_network_initiator_unknown_source", "initiator_contract", AIDA_INITIATOR_CONTRACT_V2, "_NETWORK_DEFAULT_LIMIT", "url_prefix: str | None = None", "_request_matches_text_filter", '"filtered_count"', '"returned_count"', '"has_more"'):
        if marker not in text:
            fail(f"network initiator validation missing {marker} in {path}")
    write_text(path, text)


def patch_instrumentation(path: pathlib.Path) -> None:
    if not path.exists():
        return
    original_text = read_text(path)
    text = original_text
    if "aida_clamp_navigation_timeout_ms" not in text and "from ..browser import " in text:
        text = text.replace(
            "from ..browser import ",
            "from ..browser import aida_clamp_navigation_timeout_ms, ",
            1,
        )
    if "timeout_ms: int = 60000" not in text:
        text = replace_in_function(
            text,
            "instrumentation",
            "    max_file_size: int = 200_000,\n"
            "    on_oversized: str = \"selective\",\n"
            ") -> dict:\n",
            "    max_file_size: int = 200_000,\n"
            "    on_oversized: str = \"selective\",\n"
            "    timeout_ms: int = 60000,\n"
            ") -> dict:\n",
            "instrumentation timeout signature",
        )
    if "return await _reload_with_hooks(clear_log, wait_until, timeout_ms)" not in text:
        text = replace_in_function(
            text,
            "instrumentation",
            "        return await _reload_with_hooks(clear_log, wait_until)\n",
            "        return await _reload_with_hooks(clear_log, wait_until, timeout_ms)\n",
            "instrumentation timeout forwarding",
        )
    if "async def _reload_with_hooks(clear_log: bool = True, wait_until: str = \"load\", timeout_ms: int = 60000)" not in text:
        text = text.replace(
            "async def _reload_with_hooks(clear_log: bool = True, wait_until: str = \"load\") -> dict:\n",
            "async def _reload_with_hooks(clear_log: bool = True, wait_until: str = \"load\", timeout_ms: int = 60000) -> dict:\n",
            1,
        )
    if "nav_timeout_ms = aida_clamp_navigation_timeout_ms(timeout_ms, 60000)" not in text:
        text = text.replace(
            "async def _reload_with_hooks(clear_log: bool = True, wait_until: str = \"load\", timeout_ms: int = 60000) -> dict:\n"
            "    try:\n"
            "        page = await browser_manager.get_active_page()\n",
            "async def _reload_with_hooks(clear_log: bool = True, wait_until: str = \"load\", timeout_ms: int = 60000) -> dict:\n"
            "    try:\n"
            "        try:\n"
            "            nav_timeout_ms = aida_clamp_navigation_timeout_ms(timeout_ms, 60000)\n"
            "        except Exception:\n"
            "            nav_timeout_ms = 60000\n"
            "        page = await browser_manager.get_active_page()\n",
            1,
        )
    if "page.reload(wait_until=wait_until, timeout=nav_timeout_ms)" not in text:
        text = text.replace(
            "resp = await page.reload(wait_until=wait_until)\n",
            "resp = await page.reload(wait_until=wait_until, timeout=nav_timeout_ms)\n",
            1,
        )
    if "\"timeout_ms\": nav_timeout_ms" not in text:
        text = text.replace(
            "            \"redirect_chain\": chain,\n"
            "        }\n",
            "            \"redirect_chain\": chain,\n"
            "            \"timeout_ms\": nav_timeout_ms,\n"
            "        }\n",
            1,
        )
    for marker in ("timeout_ms: int = 60000", "_reload_with_hooks(clear_log, wait_until, timeout_ms)", "page.reload(wait_until=wait_until, timeout=nav_timeout_ms)"):
        if marker not in text:
            fail(f"instrumentation validation missing {marker} in {path}")
    if text != original_text:
        write_text(path, text)


def patch_navigation_diagnostics(path: pathlib.Path, text: str) -> str:
    if "navigate_goto_exception" in text:
        return text
    if "navigation_diagnostic_snapshot" in text and "diagnostic_navigation_failure" in text:
        return text
    if "import time\n" not in text:
        text = replace_once(text, "import os\n", "import os\nimport time\n", "navigation time import")
    if "import traceback as _traceback\n" not in text:
        text = replace_once(text, "import time\n", "import time\nimport traceback as _traceback\n", "navigation traceback import")
    if "from urllib.parse import urlsplit as _urlsplit\n" not in text:
        text = replace_once(text, "import traceback as _traceback\n", "import traceback as _traceback\nfrom urllib.parse import urlsplit as _urlsplit\n", "navigation urlsplit import")
    if "from ..browser import _camoufox_debug" not in text:
        text = replace_once(
            text,
            "from ..server import mcp, browser_manager\n",
            "from ..server import mcp, browser_manager\nfrom ..browser import _camoufox_debug, _safe_text, _windows_descendant_pids\n",
            "navigation debug import",
        )
    helpers = '''def _navigation_url_diag(url: str | None) -> dict:
    text = str(url or "")
    try:
        parsed = _urlsplit(text)
        return {
            "url_len": len(text),
            "url_scheme": parsed.scheme,
            "url_host": parsed.hostname or "",
            "url_path_len": len(parsed.path or ""),
            "url_query_len": len(parsed.query or ""),
        }
    except Exception as exc:
        return {"url_len": len(text), "url_parse_error": _safe_text(exc, 240)}


async def _navigation_state(page=None, requested_page_id: str | None = None) -> dict:
    state = {
        "session_id": getattr(browser_manager, "session_id", ""),
        "requested_page_id": requested_page_id or "",
        "active_page_id": getattr(browser_manager, "active_page_id", "") or "",
        "page_count": len(getattr(browser_manager, "pages", {}) or {}),
        "context_count": len(getattr(browser_manager, "contexts", {}) or {}),
        "browser_open": getattr(browser_manager, "browser", None) is not None,
    }
    try:
        descendants = _windows_descendant_pids(os.getpid())
        state["descendant_count"] = len(descendants)
        state["descendants"] = descendants[:24]
    except Exception as exc:
        state["descendant_error"] = _safe_text(exc, 240)
    if page is None:
        return state
    try:
        state["resolved_page_id"] = browser_manager.page_id_for(page) or ""
    except Exception as exc:
        state["resolved_page_error"] = _safe_text(exc, 240)
    try:
        closed = browser_manager._page_closed(page)
        state["page_closed"] = bool(closed)
    except Exception as exc:
        state["page_closed_error"] = _safe_text(exc, 240)
    try:
        current_url = str(getattr(page, "url", "") or "")
        parsed = _urlsplit(current_url)
        state["page_url_len"] = len(current_url)
        state["page_url_host"] = parsed.hostname or ""
    except Exception as exc:
        state["page_url_error"] = _safe_text(exc, 240)
    try:
        ctx = getattr(page, "context", None)
        state["context_pages"] = len(getattr(ctx, "pages", []) or []) if ctx is not None else 0
    except Exception as exc:
        state["context_pages_error"] = _safe_text(exc, 240)
    return state


'''
    if "async def _navigation_state" not in text:
        text = replace_once(text, "@mcp.tool()\nasync def launch_browser", helpers + "@mcp.tool()\nasync def launch_browser", "navigation diagnostics helpers")
    text = replace_once(
        text,
        "        page = await browser_manager.resolve_page(page_id)\n        warnings: list[str] = []\n",
        "        page = await browser_manager.resolve_page(page_id)\n        nav_started = time.perf_counter()\n        nav_url_diag = _navigation_url_diag(url)\n        nav_state = await _navigation_state(page, page_id)\n        warnings: list[str] = []\n        _camoufox_debug(\n            \"navigate_begin\",\n            wait_until=wait_until,\n            collect_response_chain=bool(collect_response_chain),\n            clear_network_capture=bool(clear_network_capture),\n            include_title=bool(include_title),\n            pre_inject_hooks=len(pre_inject_hooks or []),\n            **nav_url_diag,\n            **nav_state,\n        )\n",
        "navigation begin diagnostics",
    )
    text = replace_once(
        text,
        "        try:\n            resp = await page.goto(url, wait_until=wait_until, timeout=30000)\n        except Exception as e:\n            msg = str(e).lower()\n",
        "        try:\n            _camoufox_debug(\n                \"navigate_goto_begin\",\n                elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n                wait_until=wait_until,\n                **nav_url_diag,\n                **(await _navigation_state(page, page_id)),\n            )\n            resp = await page.goto(url, wait_until=wait_until, timeout=30000)\n            _camoufox_debug(\n                \"navigate_goto_ok\",\n                elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n                response_status=resp.status if resp else None,\n                **nav_url_diag,\n                **(await _navigation_state(page, page_id)),\n            )\n        except Exception as e:\n            _camoufox_debug(\n                \"navigate_goto_exception\",\n                elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n                wait_until=wait_until,\n                error_type=type(e).__name__,\n                error_summary=_safe_text(e, 1000),\n                error_repr=_safe_text(repr(e), 1000),\n                error_traceback=_safe_text(\"\".join(_traceback.format_exception(type(e), e, e.__traceback__)), 4000),\n                **nav_url_diag,\n                **(await _navigation_state(page, page_id)),\n            )\n            msg = str(e).lower()\n",
        "navigation goto diagnostics",
    )
    text = replace_once(
        text,
        "                        warnings.append(f\"page usable (readyState={dom_ready})\")\n                        resp = None\n                        navigation_timed_out = True\n",
        "                        warnings.append(f\"page usable (readyState={dom_ready})\")\n                        resp = None\n                        navigation_timed_out = True\n                        _camoufox_debug(\n                            \"navigate_goto_timeout_recovered\",\n                            elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n                            ready_state=str(dom_ready),\n                            **nav_url_diag,\n                            **(await _navigation_state(page, page_id)),\n                        )\n",
        "navigation timeout recovered diagnostics",
    )
    text = replace_once(
        text,
        "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        return out\n\n    except Exception as e:\n        return {\"error\": str(e)}\n\n\nasync def _inject_hook_by_name",
        "        if title_error:\n            out[\"title_error\"] = title_error\n        out.update(await browser_manager.page_envelope(page))\n        _camoufox_debug(\n            \"navigate_complete\",\n            elapsed_ms=int((time.perf_counter() - nav_started) * 1000),\n            initial_status=initial_status,\n            final_status=out.get(\"final_status\"),\n            navigation_timed_out=bool(navigation_timed_out),\n            warnings_count=len(warnings),\n            **nav_url_diag,\n            **(await _navigation_state(page, page_id)),\n        )\n        return out\n\n    except Exception as e:\n        err_page = locals().get(\"page\")\n        err_started = locals().get(\"nav_started\")\n        err_elapsed = int((time.perf_counter() - err_started) * 1000) if err_started else 0\n        err_url_diag = locals().get(\"nav_url_diag\") or _navigation_url_diag(url)\n        _camoufox_debug(\n            \"navigate_exception\",\n            elapsed_ms=err_elapsed,\n            wait_until=wait_until,\n            error_type=type(e).__name__,\n            error_summary=_safe_text(e, 1000),\n            error_repr=_safe_text(repr(e), 1000),\n            error_traceback=_safe_text(\"\".join(_traceback.format_exception(type(e), e, e.__traceback__)), 4000),\n            **err_url_diag,\n            **(await _navigation_state(err_page, page_id)),\n        )\n        return {\"error\": str(e)}\n\n\nasync def _inject_hook_by_name",
        "navigation completion diagnostics",
    )
    for marker in ("navigate_begin", "navigate_goto_begin", "navigate_goto_exception", "navigate_exception", "async def _navigation_state"):
        if marker not in text:
            fail(f"navigation diagnostics validation missing {marker} in {path}")
    return text


HOOKING_ADD_INIT_SCRIPT = '''@mcp.tool()
async def add_init_script(
    script: str,
    name: str = "",
    persistent: bool = True,
    page_id: str | None = None,
) -> dict:
    try:
        if not isinstance(script, str) or not script.strip():
            return {"error": "script is required"}
        script_name = name.strip() if isinstance(name, str) and name.strip() else f"inline:{hashlib.sha256(script.encode('utf-8')).hexdigest()[:16]}"
        page = await browser_manager.resolve_page(page_id)
        if persistent:
            await browser_manager.add_persistent_script(script_name, script)
        else:
            await page.add_init_script(script=script)
        if script_name not in browser_manager._init_scripts:
            browser_manager._init_scripts.append(script_name)
        warning = None
        try:
            await page.evaluate(script)
        except Exception as e:
            warning = str(e)
        out = {
            "status": "injected",
            "name": script_name,
            "persistent": bool(persistent),
            "context_init": bool(persistent),
            "page_init": not bool(persistent),
            "page_id": browser_manager.page_id_for(page) if hasattr(browser_manager, "page_id_for") else page_id,
            "applied_to_current_page": warning is None,
            "contexts": len(browser_manager.contexts),
            "pages": len(browser_manager.pages),
        }
        if warning:
            out["warning"] = f"current page evaluate failed: {warning}"
        return out
    except Exception as e:
        return {"error": str(e)}
'''


def patch_hooking_init_script(path: pathlib.Path, text: str) -> str:
    markers = (
        "persistent: bool = True",
        "page_id: str | None = None",
        "browser_manager.resolve_page(page_id)",
        "\"context_init\": bool(persistent)",
        "\"page_init\": not bool(persistent)",
    )
    if all(marker in text for marker in markers):
        return text
    pattern = re.compile(
        r"@mcp\.tool\(\)\nasync def add_init_script\([\s\S]*?\n(?=\n\n@mcp\.tool\(\)\nasync def inject_hook_preset\()"
    )
    match = pattern.search(text)
    if not match:
        fail(f"hooking add_init_script validation failed {path}")
    return text[:match.start()] + HOOKING_ADD_INIT_SCRIPT + text[match.end():]


def patch_hooking(path: pathlib.Path) -> None:
    text = read_text(path)
    original_text = text
    updated = patch_jsvmp_hooking_diagnostics(path, text)
    if updated != text:
        text = updated
    text = patch_hooking_init_script(path, text)
    if "async def get_console_logs(" not in text:
        if text != original_text:
            write_text(path, text)
        return
    if "page_id: str | None = None" in text and "log.get(\"page_id\") == page_id" in text:
        if text != original_text:
            write_text(path, text)
        return
    text = replace_once(
        text,
        "async def get_console_logs(\n"
        "    level: str | None = None,\n",
        "async def get_console_logs(\n"
        "    page_id: str | None = None,\n"
        "    level: str | None = None,\n",
        "hooking console signature",
    )
    text = replace_once(
        text,
        "        if level:\n",
        "        if page_id:\n            logs = [log for log in logs if log.get(\"page_id\") == page_id]\n        if level:\n",
        "hooking console filter",
    )
    if "            \"count\": len(logs),\n" in text:
        text = replace_once(
            text,
            "            \"count\": len(logs),\n",
            "            \"count\": len(logs),\n            \"page_id\": page_id,\n            \"active_page_id\": browser_manager.active_page_id,\n            \"page_count\": len(browser_manager.pages),\n",
            "hooking console envelope",
        )
    write_text(path, text)


def validate_script_analysis(path: pathlib.Path) -> None:
    if not path.exists():
        fail(f"script analysis source missing {path}")
    text = read_text(path)
    for marker in ("async def scripts(", "async def _script_error", "\"scripts\"", "\"count\"", "scripts_error", "requested_page_id"):
        if marker not in text:
            fail(f"script analysis validation missing {marker} in {path}")


def main() -> None:
    if ROOT is None:
        fail("stage root argument is required")
    bases = [
        ROOT / "deps" / "camoufox-reverse-mcp" / "src" / "camoufox_reverse_mcp",
        ROOT / "deps" / "camoufox-runtime" / "Lib" / "site-packages" / "camoufox_reverse_mcp",
    ]
    patched = 0
    for base in bases:
        if not base.exists():
            continue
        patch_main(base / "__main__.py")
        validate_playwright_pageerror_patch(base)
        patch_browser(base / "browser.py")
        patch_navigation(base / "tools" / "navigation.py")
        patch_debugging(base / "tools" / "debugging.py")
        patch_network(base / "tools" / "network.py")
        patch_instrumentation(base / "tools" / "instrumentation.py")
        patch_hooking(base / "tools" / "hooking.py")
        validate_script_analysis(base / "tools" / "script_analysis.py")
        patched += 1
    if patched == 0:
        fail(f"no camoufox_reverse_mcp package found under {ROOT}")
    print(f"Patched Camoufox reverse MCP multipage support in {patched} package copies")


if __name__ == "__main__":
    main()
