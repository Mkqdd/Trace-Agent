__all__ = ["draw_graph_pyvis"]


def __getattr__(name: str):
    if name == "draw_graph_pyvis":
        from .graph_drawer_pyvis import draw_graph_pyvis

        return draw_graph_pyvis
    raise AttributeError(name)
