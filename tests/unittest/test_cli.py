import subprocess


def test_cli(server):
    """Test that the cycurl CLI can perform basic GET requests."""
    result = subprocess.check_output(
        f"cycurl {server.url}",
        shell=True,
        text=True,
        timeout=30,
    )
    # Should look like HTTP response:
    assert "Hello, world!" in result
