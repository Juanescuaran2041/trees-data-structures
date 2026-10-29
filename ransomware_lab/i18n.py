from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ransomware_lab.diagrams import DiagramLabels
from ransomware_lab.telemetry import BehaviorFeature

ENGLISH = "en"
SPANISH = "es"

LANGUAGE_NAMES: Mapping[str, str] = {ENGLISH: "English", SPANISH: "Español"}

_PHRASES: Mapping[str, Mapping[str, str]] = {
    ENGLISH: {
        "app.title": "Ransomware Behavior Lab",
        "app.tagline": "Defensive behavior detector built on a hand-written CART decision tree.",
        "app.disclaimer": "Synthetic telemetry by default. Results demonstrate the method, not field accuracy.",
        "sidebar.language": "Language",
        "sidebar.data": "Training data",
        "sidebar.source.synthetic": "Synthetic",
        "sidebar.source.csv": "Upload CSV",
        "sidebar.csv.prompt": "CSV with columns: {columns}",
        "sidebar.model": "Model",
        "sidebar.criterion": "Impurity criterion",
        "sidebar.max_depth": "Maximum depth",
        "sidebar.min_samples_leaf": "Minimum samples per leaf",
        "sidebar.threshold": "Risk threshold",
        "sidebar.threshold.help": "Lower threshold catches stealth attacks at the cost of false positives.",
        "sidebar.retrain": "Retrain model",
        "sidebar.reset": "Reset lab",
        "metrics.title": "Model quality",
        "metrics.recall": "Recall",
        "metrics.precision": "Precision",
        "metrics.accuracy": "Accuracy",
        "metrics.worst_recall": "Worst fold recall",
        "metrics.caption": "Stratified {folds}-fold cross-validation over {samples} observations from {source}.",
        "tree.title": "Decision tree",
        "tree.caption": "Height {height}, {leaves} leaves, {nodes} nodes. The highlighted path is the one taken by the selected process.",
        "processes.title": "Process tree",
        "processes.spawn": "Spawn process",
        "processes.selected": "Selected process",
        "processes.parent": "Attach under",
        "assessment.title": "Assessment",
        "assessment.verdict": "Verdict",
        "assessment.risk": "Risk",
        "assessment.ground_truth": "Ground truth",
        "assessment.correct": "The detector agrees with the ground truth.",
        "assessment.false_negative": "False negative: this process is ransomware and went undetected.",
        "assessment.false_positive": "False positive: this process is benign and was flagged.",
        "assessment.reasons": "Why this verdict",
        "assessment.leaf_support": "Leaf supported by {samples} training observations.",
        "evasion.title": "Evasion lab",
        "evasion.caption": "Move the readings of the selected process and watch when the detector loses it.",
        "triage.title": "Triage queue",
        "triage.caption": "Max-heap ordered by risk; ties keep arrival order.",
        "triage.empty": "No process is currently flagged as ransomware.",
        "triage.pid": "PID",
        "triage.image": "Image",
        "triage.risk": "Risk",
        "triage.depth": "Lineage depth",
        "importance.title": "Feature importance",
        "importance.caption": "Weighted impurity decrease contributed by each feature.",
        "verdict.ransomware": "RANSOMWARE",
        "verdict.benign": "BENIGN",
        "label.suspect": "SUSPECT",
        "label.samples": "samples",
        "label.profile": "profile",
        "error.csv": "The CSV could not be read: {detail}",
        "error.csv_required": "Upload a CSV file to train with your own telemetry.",
        "feature.files_per_sec": "Files written per second",
        "feature.entropy": "Payload entropy (bits)",
        "feature.rename_ratio": "Rename ratio",
        "feature.shadow_delete": "Shadow copy deletion",
        "feature.dirs_touched": "Directories touched",
    },
    SPANISH: {
        "app.title": "Laboratorio de comportamiento de ransomware",
        "app.tagline": "Detector defensivo por comportamiento sobre un árbol de decisión CART escrito a mano.",
        "app.disclaimer": "Telemetría sintética por defecto. Los resultados demuestran el método, no la eficacia real.",
        "sidebar.language": "Idioma",
        "sidebar.data": "Datos de entrenamiento",
        "sidebar.source.synthetic": "Sintéticos",
        "sidebar.source.csv": "Subir CSV",
        "sidebar.csv.prompt": "CSV con las columnas: {columns}",
        "sidebar.model": "Modelo",
        "sidebar.criterion": "Criterio de impureza",
        "sidebar.max_depth": "Profundidad máxima",
        "sidebar.min_samples_leaf": "Muestras mínimas por hoja",
        "sidebar.threshold": "Umbral de riesgo",
        "sidebar.threshold.help": "Bajar el umbral detecta ataques sigilosos a cambio de más falsos positivos.",
        "sidebar.retrain": "Reentrenar modelo",
        "sidebar.reset": "Reiniciar laboratorio",
        "metrics.title": "Calidad del modelo",
        "metrics.recall": "Recall",
        "metrics.precision": "Precisión",
        "metrics.accuracy": "Exactitud",
        "metrics.worst_recall": "Peor recall por pliegue",
        "metrics.caption": "Validación cruzada estratificada de {folds} pliegues sobre {samples} observaciones de {source}.",
        "tree.title": "Árbol de decisión",
        "tree.caption": "Altura {height}, {leaves} hojas, {nodes} nodos. El camino resaltado es el que recorre el proceso seleccionado.",
        "processes.title": "Árbol de procesos",
        "processes.spawn": "Crear proceso",
        "processes.selected": "Proceso seleccionado",
        "processes.parent": "Colgar de",
        "assessment.title": "Evaluación",
        "assessment.verdict": "Veredicto",
        "assessment.risk": "Riesgo",
        "assessment.ground_truth": "Verdad de referencia",
        "assessment.correct": "El detector coincide con la verdad de referencia.",
        "assessment.false_negative": "Falso negativo: este proceso es ransomware y no fue detectado.",
        "assessment.false_positive": "Falso positivo: este proceso es benigno y fue marcado.",
        "assessment.reasons": "Por qué este veredicto",
        "assessment.leaf_support": "Hoja respaldada por {samples} observaciones de entrenamiento.",
        "evasion.title": "Laboratorio de evasión",
        "evasion.caption": "Mueve las lecturas del proceso seleccionado y observa cuándo el detector lo pierde.",
        "triage.title": "Cola de triaje",
        "triage.caption": "Montículo máximo ordenado por riesgo; los empates conservan el orden de llegada.",
        "triage.empty": "Ningún proceso está marcado como ransomware en este momento.",
        "triage.pid": "PID",
        "triage.image": "Imagen",
        "triage.risk": "Riesgo",
        "triage.depth": "Profundidad de linaje",
        "importance.title": "Importancia de características",
        "importance.caption": "Reducción de impureza ponderada que aporta cada característica.",
        "verdict.ransomware": "RANSOMWARE",
        "verdict.benign": "BENIGNO",
        "label.suspect": "SOSPECHOSO",
        "label.samples": "muestras",
        "label.profile": "perfil",
        "error.csv": "No se pudo leer el CSV: {detail}",
        "error.csv_required": "Sube un archivo CSV para entrenar con tu propia telemetría.",
        "feature.files_per_sec": "Archivos escritos por segundo",
        "feature.entropy": "Entropía del contenido (bits)",
        "feature.rename_ratio": "Proporción de renombrados",
        "feature.shadow_delete": "Borrado de copias de seguridad",
        "feature.dirs_touched": "Directorios tocados",
    },
}


@dataclass(frozen=True, slots=True)
class Translator:
    language: str = ENGLISH

    def __post_init__(self) -> None:
        if self.language not in _PHRASES:
            raise KeyError(f"unsupported language {self.language!r}")

    def __call__(self, key: str, **placeholders: object) -> str:
        phrase = _PHRASES[self.language].get(key) or _PHRASES[ENGLISH].get(key, key)
        return phrase.format(**placeholders) if placeholders else phrase

    def feature(self, feature: BehaviorFeature) -> str:
        return self(f"feature.{feature.column}")

    def diagram_labels(self) -> DiagramLabels:
        return DiagramLabels(
            feature_label=self.feature,
            samples=self("label.samples"),
            risk=self("assessment.risk"),
            ransomware=self("verdict.ransomware"),
            benign=self("verdict.benign"),
            suspect=self("label.suspect"),
            profile=self("label.profile"),
        )


def supported_languages() -> tuple[str, ...]:
    return tuple(_PHRASES)


def phrase_keys(language: str) -> frozenset[str]:
    return frozenset(_PHRASES[language])
