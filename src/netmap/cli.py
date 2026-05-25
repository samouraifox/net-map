"""net-map CLI entry point.

Subcommands are registered in later tasks. This stub keeps the package importable
and gives us a `netmap version` smoke command.
"""
import typer

from netmap import __version__

app = typer.Typer(help="net-map — continuous inventory + topology visualizer", no_args_is_help=True)


@app.callback()
def _callback() -> None:
    """net-map — continuous inventory + topology visualizer."""


@app.command()
def version() -> None:
    """Print the installed netmap version."""
    typer.echo(__version__)
