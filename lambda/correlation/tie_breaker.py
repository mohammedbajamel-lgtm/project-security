from .time_window import timestamp

PRIORITY = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def winner(findings):
    return min(findings, key=lambda f: (PRIORITY.get(f.severity, 9), timestamp(f), f.finding_id))
