from ...knowledge_plugins.functions import Function
from .base import InsightBase


class SwitchesInsight(InsightBase):
    """
    Classify functions with large switch-cases.
    """

    def __init__(self, *args, case_threshold: int=8, **kwargs):
        super().__init__(*args, **kwargs)

        self._case_threshold = case_threshold

        self.result = [ ]

        self.analyze()

    def analyze(self):
        for _, jumptable in self.cfg.jump_tables.items():
            if len(jumptable.jumptable_entries) < self._case_threshold:
                continue

            item = {
                'description': 'Found a switch-case struct with %d cases.' % len(jumptable.jumptable_entries),
                'ref_at': jumptable.ins_addr,
                'func_addr': jumptable.func_addr,
                'func_name': self.kb.functions[jumptable.func_addr].name,
            }

            # determine blocks within the switch-case construct
            func = self.kb.functions[jumptable.func_addr]
            func_start = func.addr
            func_end_block = func.get_block(max(func.block_addrs_set))
            func_end = func_end_block.addr + func_end_block.size

            # find strings that are referenced in the switch-case construct
            top_strings = [ ]
            for xref in self.kb.xrefs.get_xrefs_by_ins_addr_region(func_start, func_end):
                if xref.memory_data is not None and xref.memory_data.sort == 'string':
                    top_strings.append(xref.memory_data.content.decode('utf-8'))
            top_strings = list(sorted(top_strings, key=lambda x: len(x), reverse=True))[:8]

            top_strings_text = [
                "# Top 8 strings:",
            ]
            for t in top_strings:
                top_strings_text.append("    " + repr(t))
            top_strings_text = "\n".join(top_strings_text)

            # find functions that are referenced in the switch-case construct
            top_functions = set()
            for src, dst in func.transition_graph.edges():
                if isinstance(dst, Function):
                    top_functions.add(dst)

            top_functions_text = [
                "# Top 8 functions called:"
            ]
            for t in sorted(top_functions, key=lambda func: len(func.name), reverse=True)[:8]:
                top_functions_text.append("    " + t.name)
            top_functions_text = "\n".join(top_functions_text)

            item['description'] += "\n" + top_strings_text + "\n" + top_functions_text
            item['top_strings'] = top_strings
            item['top_functions'] = top_functions

            self.result.append(item)


from angr.analyses import AnalysesHub
AnalysesHub.register_default('Insight_Switches', SwitchesInsight)