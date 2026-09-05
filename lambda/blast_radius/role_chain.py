"""Cycle-safe bounded BFS for role assumption paths."""


def find_assumable_roles(
    start: str, trust_graph: dict[str, list[str]], *, max_depth: int = 5
) -> dict:
    queue, paths, reached, maximum = [(start, [start], 0)], [], set(), False
    while queue:
        principal, path, depth = queue.pop(0)
        if depth >= max_depth:
            maximum = maximum or bool(trust_graph.get(principal))
            continue
        for role in trust_graph.get(principal, []):
            if role in path:
                continue
            new_path = [*path, role]
            paths.append(new_path)
            reached.add(role)
            queue.append((role, new_path, depth + 1))
    return {
        "reachable_roles": sorted(reached),
        "assumption_paths": paths,
        "max_depth_reached": maximum,
    }
