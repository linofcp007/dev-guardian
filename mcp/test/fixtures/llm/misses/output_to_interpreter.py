"""llm-output-to-interpreter-py -- nothing here may fire.

Each function is either a false-positive class measured on the corpus, the
near-miss one of the rule's regexes exists to exclude, or a fix the rule's
message prescribes.
"""

import ast
import json


class ConfiguracaoDoAgente:
    # Measured (SuperAGI): a dict whose NAME merely contains "agent" is not a
    # model. The receiver regex anchors the model word at the END of the name.
    def construir(self, stored_agent_config):
        objetivos = {}
        for chave, valor in stored_agent_config.items():
            objetivos[chave] = eval(valor)
        return objetivos


def query_builder(cursor, tabela):
    # A query built by the program's own code: no model anywhere.
    cursor.execute(build_select(tabela))


class Pesquisa:
    # Measured shape (MetaGPT's research action): model-written keywords sent
    # to a SEARCH engine. `.run` is an interpreter only on a REPL, shell or
    # database receiver.
    def __init__(self, llm, search_engine):
        self.llm = llm
        self.search_engine = search_engine

    async def pesquisar(self, topico):
        termos = await self.llm.aask(topico)
        return await self.search_engine.run(termos)


def parse_as_data(resp):
    # The prescribed fix: parse the model's text as DATA.
    return json.loads(resp.choices[0].message.content)


def parse_literal(model_reply):
    # ast.literal_eval evaluates literals only; it is what eval() should have been.
    return ast.literal_eval(model_reply)


def bound_parameter(cursor, resp):
    # A model value as a BOUND parameter is data; only the query text is a sink.
    cursor.execute("SELECT * FROM produtos WHERE nome = %s", (resp.choices[0].message.content,))


def eval_of_settings(model_settings):
    # A name that says model CONFIGURATION, not model output.
    return eval(model_settings)
