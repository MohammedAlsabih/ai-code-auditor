import pytest

from auditor.cli import main


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "ai-code-auditor 0.1.0" in capsys.readouterr().out
