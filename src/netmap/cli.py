"""net-map CLI entry point.

Subcommands are registered in later tasks. This stub keeps the package importable
and gives us a `netmap version` smoke command.
"""
import typer

from netmap import __version__

app = typer.Typer(help="net-map — continuous inventory + topology visualizer", no_args_is_help=True)


# Typer ≥0.25 collapses a single-command app onto the root, which breaks
# `netmap version` (the arg gets reinterpreted). The empty callback forces
# group/multi-command mode. Remove this whole block once a second subcommand
# is registered (it becomes redundant from T18 onward).
@app.callback()
def _callback() -> None:
    pass


@app.command()
def version() -> None:
    """Print the installed netmap version."""
    typer.echo(__version__)
