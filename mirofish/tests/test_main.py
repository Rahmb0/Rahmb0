from src.main import run


def test_run_executes(capsys):
    run()
    captured = capsys.readouterr()
    assert "MiroFish" in captured.out
