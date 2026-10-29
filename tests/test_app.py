from __future__ import annotations

import pytest

from ransomware_lab.i18n import SPANISH, Translator

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
RUN_TIMEOUT_SECONDS = 60


def launched_app() -> AppTest:
    app = AppTest.from_file("app.py", default_timeout=RUN_TIMEOUT_SECONDS)
    app.run()
    return app


def test_app_renders_without_exceptions():
    app = launched_app()
    assert not app.exception
    assert app.title[0].value == "Ransomware Behavior Lab"
    assert len(app.metric) >= 4


def test_switching_to_spanish_translates_the_headings():
    app = launched_app()
    app.sidebar.radio[0].set_value(SPANISH).run()
    assert not app.exception
    assert app.title[0].value == Translator(SPANISH)("app.title")


def test_spawning_a_process_grows_the_process_tree():
    app = launched_app()
    before = len(app.session_state["lab"].process_tree)
    app.button(key="spawn").click().run()
    assert not app.exception
    assert len(app.session_state["lab"].process_tree) == before + 1


def test_lowering_the_threshold_reaches_the_detector():
    app = launched_app()
    app.slider(key="risk-threshold").set_value(0.2).run()
    assert not app.exception
    assert app.session_state["lab"].detector.risk_threshold == pytest.approx(0.2)
