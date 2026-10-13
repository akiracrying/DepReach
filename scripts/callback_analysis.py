"""Verify direct callback consumption without conflating separate call sites.

The callback edge stays attached to the supplying caller, with the consumer's
invocation location as evidence. Adding a global consumer->callback edge would
incorrectly propagate arguments from unreachable callers into reachable ones.
Unknown consumers remain speculative; escaped values do not prove invocation.
"""
import ast
from collections import defaultdict


def _body_nodes(function):
    for statement in function.body:
        yield from _scope_nodes(statement)


def _scope_nodes(node):
    yield node
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    for child in ast.iter_child_nodes(node):
        yield from _scope_nodes(child)


def _classify(function, parameter):
    nodes = list(_body_nodes(function))
    # Rebinding and closures require dataflow. Do not attribute the invocation
    # of a replacement value to the original callback.
    if any(isinstance(n, (ast.Global, ast.Nonlocal)) for n in nodes):
        return "unresolved", []
    if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) for n in nodes):
        return "unresolved", []
    if any(isinstance(n, ast.Name) and n.id == parameter and isinstance(n.ctx, (ast.Store, ast.Del)) for n in nodes):
        return "unresolved", []
    if any(isinstance(n, (ast.Import, ast.ImportFrom, ast.ExceptHandler, ast.Match)) for n in nodes):
        return "unresolved", []
    calls = [n for n in nodes if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == parameter]
    if calls:
        return "invoked", [n.lineno for n in calls]
    if any(isinstance(n, ast.Name) and n.id == parameter and isinstance(n.ctx, ast.Load) for n in nodes):
        return "escaped", []
    return "unused", []


def _parameter(function, call):
    positional = [a.arg for a in [*function.args.posonlyargs, *function.args.args]]
    keyword_only = [a.arg for a in function.args.kwonlyargs]
    keywords = call["keyword_names"]
    count = call["positional_count"]
    if call["binding_uncertain"] or len(keywords) != len(set(keywords)):
        return None
    # Check the whole argument binding, not just the callback position.
    if count > len(positional) and not function.args.vararg:
        return None
    positional_only = {a.arg for a in function.args.posonlyargs}
    if any(k in positional[:count] or (k in positional_only and not function.args.kwarg) for k in keywords):
        return None
    if any(k not in positional + keyword_only and not function.args.kwarg for k in keywords):
        return None
    required = positional[:len(positional) - len(function.args.defaults)]
    if any(p not in positional[:count] and p not in keywords for p in required):
        return None
    if any(a.arg not in keywords and default is None for a, default in zip(function.args.kwonlyargs, function.args.kw_defaults)):
        return None
    position, keyword = call["argument_position"], call["argument_keyword"]
    if position is not None:
        return positional[position] if position < len(positional) else None
    return keyword if keyword in positional + keyword_only and keyword not in positional_only else None


def _functions(graph, parsed):
    identities = defaultdict(list)
    for name, info in graph.symbols.items():
        if info["kind"] == "function":
            identities[(info["file"], info["line"])].append(name)
    functions = {}
    for _, tree, file, _ in parsed:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                names = identities[(file, node.lineno)]
                if len(names) == 1:
                    functions[names[0]] = node
    return functions


def infer_parameter_returns(graph, parsed):
    """Exact summaries for plain functions returning an unchanged argument.

    Bodies with storage, invocation, rebinding or additional control flow are
    not identity functions. In particular, async/generator/decorated functions
    cannot be treated as synchronous callback factories.
    """
    summaries = {}
    for symbol, function in _functions(graph, parsed).items():
        if function.decorator_list or symbol in graph.ambiguous_symbols or symbol.rpartition(".")[0] in graph.classes:
            continue
        body = function.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]
        if len(body) != 1 or not isinstance(body[0], ast.Return) or not isinstance(body[0].value, ast.Name):
            continue
        parameter = body[0].value.id
        parameters = [a.arg for a in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]]
        if parameter in parameters:
            summaries[symbol] = (function, parameter)
    return summaries


def argument_binding(node, position, keyword):
    return {"argument_position": position, "argument_keyword": keyword,
            "binding_uncertain": any(isinstance(arg, ast.Starred) for arg in node.args) or any(kw.arg is None for kw in node.keywords),
            "positional_count": len(node.args), "keyword_names": [kw.arg for kw in node.keywords]}


def returned_argument(graph, consumer, node):
    summary = graph.parameter_returns.get(consumer)
    if summary is None:
        return None
    function, parameter = summary
    arguments = [(argument, index, None) for index, argument in enumerate(node.args)]
    arguments.extend((kw.value, None, kw.arg) for kw in node.keywords)
    for argument, position, keyword in arguments:
        if _parameter(function, argument_binding(node, position, keyword)) == parameter:
            return argument
    # Default values and **kwargs need their own binding model.
    return None


def resolve_callbacks(graph, parsed):
    functions = _functions(graph, parsed)
    calls = []
    for call in graph.calls:
        if call.get("edge_kind") != "passed_callable_may_be_invoked":
            calls.append(call)
            continue
        consumer = graph.resolve(call.get("callback_consumer"))
        function = functions.get(consumer)
        parameter, kind, lines = None, "unresolved", []
        if (function is not None and not function.decorator_list
                and consumer not in graph.ambiguous_symbols
                and consumer.rpartition(".")[0] not in graph.classes
                and not any(isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await)) for n in _body_nodes(function))):
            parameter = _parameter(function, call)
            if parameter:
                kind, lines = _classify(function, parameter)
                summary = graph.parameter_returns.get(consumer)
                if summary and parameter == summary[1]:
                    kind = "returned"
        record = {"caller": call["caller"], "file": call["file"], "line": call["line"], "column": call.get("column"),
                  "consumer": consumer, "callback": call["target"], "parameter": parameter,
                  "disposition": kind, "invocation_lines": lines}
        if kind == "returned":
            record["return_line"] = function.body[-1].lineno
            record["result_usage"] = call.get("result_usage", "unresolved")
            record["basis"] = "unchanged_parameter_return"
        if function is not None:
            record["consumer_file"] = graph.symbols[consumer]["file"]
        graph.callback_models.append(record)
        if kind == "invoked":
            call["edge_kind"] = "callback_invocation"
            call["callback_evidence"] = record
            calls.append(call)
        elif kind == "unresolved":
            graph.issue("callback_argument", call["file"], call["line"], call["caller"])
            calls.append(call)
        elif kind == "escaped" or (kind == "returned" and call.get("result_usage") not in {"discarded", "immediately_invoked"}):
            graph.issue("callback_escapes", call["file"], call["line"], call["caller"], possible_targets=[call["target"]])
        # A parameter unused by a known consumer has no invocation edge.
    graph.calls = calls


def scope_parameter_calls(graph, parsed):
    """Bound formal-call uncertainty using every modeled reachable call site.

    Unknown bindings, callback entry, first-party roots and mixed expressions
    remain unbounded. We do not connect a consumer globally to callbacks from
    unrelated or unreachable calls. Other unresolved graph behavior still
    blocks negative conclusions through the usual diagnostic traversal.
    """
    reachable = graph.root_parents()
    functions = _functions(graph, parsed)
    incoming = defaultdict(list)
    for call in graph.calls:
        if call["caller"] in reachable and not call.get("import"):
            incoming[call.get("resolved")].append(call)
    models = defaultdict(list)
    for model in graph.callback_models:
        if model["disposition"] == "invoked":
            key = (model["consumer"], model["parameter"], model["caller"], model["file"], model["line"], model.get("column"))
            models[key].append(model)
    for diagnostic in graph.diagnostics:
        consumer = diagnostic["caller"]
        function = functions.get(consumer)
        if (diagnostic["reason"] != "unresolved_call" or function is None or consumer in graph.roots
                or consumer not in reachable or not incoming[consumer]):
            continue
        at_line = [node for node in _body_nodes(function) if isinstance(node, ast.Call) and node.lineno == diagnostic["line"]]
        # Diagnostics currently combine calls on the same source line. Only
        # scope them if every call on that line is an accounted formal call.
        if not at_line or any(not isinstance(node.func, ast.Name) for node in at_line):
            continue
        parameters = {node.func.id for node in at_line}
        targets, sites = set(), []
        complete = True
        for parameter in parameters:
            for call in incoming[consumer]:
                key = (consumer, parameter, call["caller"], call["file"], call["line"], call.get("column"))
                matches = models.get(key, [])
                if len(matches) != 1 or diagnostic["line"] not in matches[0]["invocation_lines"]:
                    complete = False
                    break
                targets.add(matches[0]["callback"])
                sites.append({"caller": call["caller"], "file": call["file"], "line": call["line"],
                              "column": call.get("column"), "parameter": parameter, "callback": matches[0]["callback"]})
            if not complete:
                break
        if complete:
            diagnostic["possible_targets"] = sorted(targets)
            diagnostic["scope_basis"] = "all_modeled_reachable_callback_bindings"
            diagnostic["binding_sites"] = sites[:5]
            diagnostic["binding_sites_total"] = len(sites)
