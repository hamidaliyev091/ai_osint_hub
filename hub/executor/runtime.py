"""Tool execution runtime — subprocess management only.

Responsibility: validate, build command, execute via subprocess, handle errors.
Does NOT: parse output, extract entities, decide anything.
"""

from dataclasses import dataclass, field
from typing import Literal, Optional
import subprocess
import time
import shlex

from hub.registry import get_tool, resolve, validate as registry_validate


@dataclass
class ExecutionResult:
    tool: str
    target: str
    status: Literal["success", "timeout", "error", "tool_not_found", "blocked_dangerous"]
    raw_stdout: str = ""
    raw_stderr: str = ""
    exit_code: int = -1
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)


def execute(tool_name: str, params: dict, timeout_s: Optional[int] = None,
            allow_dangerous: bool = False, dry_run: bool = False) -> ExecutionResult:
    """Execute a tool via subprocess.

    Args:
        tool_name: Registered tool name (must be in registry)
        params: Tool-specific params matching the tool's param schema
        timeout_s: Override default timeout (None = use registry default)
        allow_dangerous: Must be True for dangerous tools (hashcat, hydra)
        dry_run: If True, return the command without executing

    Returns:
        ExecutionResult with status, raw output, and metadata.
    """
    # 1. Validate tool exists
    tool_meta = get_tool(tool_name)
    if tool_meta is None:
        return ExecutionResult(
            tool=tool_name, target=str(params), status="tool_not_found",
            errors=[f"Unknown tool: {tool_name}"],
        )

    # 2. Validate params
    is_valid, error = registry_validate(tool_name, params)
    if not is_valid:
        return ExecutionResult(
            tool=tool_name, target=str(params), status="error",
            errors=[error or "Parameter validation failed"],
        )

    # 3. Safety gate: dangerous tools
    if tool_meta.dangerous and not allow_dangerous:
        return ExecutionResult(
            tool=tool_name, target=str(params), status="blocked_dangerous",
            errors=[f"Tool '{tool_name}' requires explicit authorization. "
                    f"Set allow_dangerous=True to execute."],
        )

    # 4. Build command
    cmd_parts = [tool_meta.binary]
    for pname, pvalue in params.items():
        cli_flag = tool_meta.cli_map.get(pname)
        if cli_flag is None:
            # Positional param
            if isinstance(pvalue, list):
                cmd_parts.extend([str(v) for v in pvalue])
            else:
                cmd_parts.append(str(pvalue))
        else:
            if isinstance(pvalue, list):
                for v in pvalue:
                    cmd_parts.extend([cli_flag, str(v)])
            elif isinstance(pvalue, bool):
                if pvalue:
                    cmd_parts.append(cli_flag)
            else:
                cmd_parts.extend([cli_flag, str(pvalue)])

    # Add tool-specific extra flags from registry (P2-2)
    for flag in tool_meta.extra_flags:
        cmd_parts.append(flag)

    if dry_run:
        return ExecutionResult(
            tool=tool_name, target=str(params), status="success",
            raw_stdout=shlex.join(cmd_parts), duration_ms=0,
        )

    # 5. Execute
    effective_timeout = timeout_s if timeout_s is not None else tool_meta.timeout_s
    start = time.monotonic()

    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
        duration = int((time.monotonic() - start) * 1000)

        if result.returncode != 0:
            return ExecutionResult(
                tool=tool_name, target=str(params), status="error",
                raw_stdout=result.stdout, raw_stderr=result.stderr,
                exit_code=result.returncode, duration_ms=duration,
                errors=[f"Non-zero exit code: {result.returncode}"],
            )

        return ExecutionResult(
            tool=tool_name, target=str(params), status="success",
            raw_stdout=result.stdout, raw_stderr=result.stderr,
            exit_code=0, duration_ms=duration,
        )

    except subprocess.TimeoutExpired:
        duration = int((time.monotonic() - start) * 1000)
        return ExecutionResult(
            tool=tool_name, target=str(params), status="timeout",
            errors=[f"Tool timed out after {effective_timeout}s"],
            duration_ms=duration,
        )

    except FileNotFoundError:
        return ExecutionResult(
            tool=tool_name, target=str(params), status="tool_not_found",
            errors=[f"Binary '{tool_meta.binary}' not found in PATH"],
        )

    except Exception as e:
        duration = int((time.monotonic() - start) * 1000)
        return ExecutionResult(
            tool=tool_name, target=str(params), status="error",
            errors=[f"Unexpected error: {str(e)}"],
            duration_ms=duration,
        )
