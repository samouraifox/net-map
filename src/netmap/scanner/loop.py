"""Foreground asyncio scan loop + per-scan dispatcher.

`scan_loop` runs while the process is alive and ticks on `cfg.scan.interval_s`.
`maybe_run` opens a scan row, registers the (mode, target) pair in the
in-flight set, and dispatches the actual scan work as a background task.
"""
