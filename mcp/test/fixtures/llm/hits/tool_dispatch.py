"""llm-tool-name-dispatch-py -- every `# BUG` line fires the rule exactly once.

A tool or function NAME the model chose, used to look up code by name with
no allowlist between them: the model can reach any attribute, global or
module, not just the tools it was offered.
"""

import importlib
import json


class Ferramentas:
    def despachar(self, resp):
        chamada = resp.choices[0].message.tool_calls[0]
        nome = chamada.function.name
        return getattr(self, nome)(**json.loads(chamada.function.arguments))  # BUG: getattr on the model's tool name


def legacy_function_call(resp):
    nome = resp.choices[0].message.function_call.name
    return globals()[nome]()  # BUG: the pre-tools function_call, through globals()


def legacy_dict(mensagem):
    return locals()[mensagem["function_call"]["name"]]  # BUG: the same, read as a dict


def plugin_module(chamada):
    return importlib.import_module(chamada["function"]["name"])  # BUG: a module named by the model


def anthropic_tool_use(client, pergunta, ferramentas):
    msg = client.messages.create(model="claude-sonnet-4-5", max_tokens=1024, tools=ferramentas, messages=[{"role": "user", "content": pergunta}])
    for block in msg.content:
        if block.type == "tool_use":
            return __import__(block.name)  # BUG: an Anthropic tool_use block's name


FERRAMENTAS = {"meteorologia", "calendario"}


class GuardasQueNaoGuardam:
    """Review of the pack, I-1: checks that LOOK like an allowlist and are not."""

    def so_avisa(self, tc):
        nome = tc.function.name
        if nome not in FERRAMENTAS:
            logger.warning("ferramenta desconhecida: %s", nome)
        return getattr(self, nome)()  # BUG: the guard only warns, and the lookup runs anyway

    def nao_faz_nada(self, tc):
        nome = tc.function.name
        if nome not in FERRAMENTAS:
            pass
        return getattr(self, nome)()  # BUG: the guard does nothing

    def qualquer_atributo(self, tc):
        nome = tc.function.name
        if nome in dir(self):
            return getattr(self, nome)()  # BUG: dir(self) is every attribute, not an allowlist
        return None

    def substring(self, tc):
        nome = tc.function.name
        if nome in "meteorologia calendario":
            return getattr(self, nome)()  # BUG: `in` a STRING is a substring test ("teo" passes)
        return None

    def do_dicionario_da_classe(self, tc):
        nome = tc.function.name
        if nome in type(self).__dict__:
            return getattr(self, nome)()  # BUG: the class's __dict__ holds every method
        return None

    def vars_com_saida(self, tc):
        nome = tc.function.name
        if nome not in vars(self):
            raise KeyError(nome)
        return getattr(self, nome)()  # BUG: vars(self) is every instance attribute

    def ramo_senao(self, tc):
        nome = tc.function.name
        if nome in FERRAMENTAS:
            return getattr(self, nome)()  # excluded: the THEN arm of the allowlist check
        else:
            return getattr(self, nome)()  # BUG: the ELSE arm of the same check is where the name is NOT allowed
