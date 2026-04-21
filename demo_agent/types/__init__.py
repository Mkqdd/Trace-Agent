__all__ = ["normalize_alert"]


def __getattr__(name: str):
    if name == "normalize_alert":
        from .event import normalize_alert

        return normalize_alert
    raise AttributeError(name)
