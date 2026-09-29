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


MODOS = {"rapido", "completo"}
FORNECEDORES = {"openai", "anthropic"}


class GuardasDeOutraCoisa:
    """Review of the pack, round 2 (I-A): a membership test on something ELSE is
    not a guard of the tool name, and a guard only counts where its exit is
    unconditional and belongs to this function or loop."""

    def modo(self, tc, modo):
        nome = tc.function.name
        if modo not in MODOS:
            raise ValueError(modo)
        return getattr(self, nome)()  # BUG: the check is on the MODE, not the name

    def fornecedor(self, tc):
        nome = tc.function.name
        if self.provider in FORNECEDORES:
            return getattr(self, nome)()  # BUG: the check is on the provider
        return None

    def chave_do_payload(self, tc, payload):
        nome = tc.function.name
        if "tool_calls" in payload:
            return getattr(self, nome)()  # BUG: a key test on the payload
        return None

    def papel_no_contexto(self, tc):
        nome = tc.function.name
        if "role" not in self.context:
            return None
        return getattr(self, nome)()  # BUG: a key test on the context

    def primeiro_segundo(self, tc1, tc2):
        primeiro = tc1.function.name
        segundo = tc2.function.name
        if primeiro not in FERRAMENTAS:
            raise ValueError(primeiro)
        return getattr(self, segundo)()  # BUG: the FIRST name was checked, the second is dispatched

    def religado(self, tc, tc2):
        nome = tc.function.name
        if nome not in FERRAMENTAS:
            raise ValueError(nome)
        nome = tc2.function.name
        return getattr(self, nome)()  # BUG: the name was rebound after the check

    def saida_condicional(self, tc, estrito):
        nome = tc.function.name
        if nome not in FERRAMENTAS:
            if estrito:
                raise ValueError(nome)
        return getattr(self, nome)()  # BUG: the raise only happens when `estrito`

    def return_de_outra_funcao(self, tc):
        nome = tc.function.name
        if nome not in FERRAMENTAS:
            def aviso():
                return nome
        return getattr(self, nome)()  # BUG: that `return` belongs to a nested def

    def continue_de_outro_ciclo(self, tc, avisos):
        nome = tc.function.name
        if nome not in FERRAMENTAS:
            for aviso in avisos:
                continue
        return getattr(self, nome)()  # BUG: that `continue` belongs to an inner loop

    def elif_sem_saida_antes(self, tc):
        nome = tc.function.name
        if nome == "ajuda":
            pass
        elif nome not in FERRAMENTAS:
            raise ValueError(nome)
        return getattr(self, nome)()  # BUG: when nome == "ajuda" nothing was checked (the first branch does not exit)

    def elif_que_so_avisa(self, tc):
        nome = tc.function.name
        if not nome:
            raise ValueError("vazio")
        elif nome not in FERRAMENTAS:
            logger.warning("desconhecida %s", nome)
        return getattr(self, nome)()  # BUG: the elif only warns

    def conjunto_de_dir(self, tc):
        nome = tc.function.name
        if nome in set(dir(self)):
            return getattr(self, nome)()  # BUG: set(dir(self)) is still every attribute
        return None

    def chaves_do_dict(self, tc):
        nome = tc.function.name
        if nome not in self.__dict__.keys():
            raise KeyError(nome)
        return getattr(self, nome)()  # BUG: __dict__.keys() is every instance attribute

    def f_string(self, tc, a, b):
        nome = tc.function.name
        if nome in f"{a} {b}":
            return getattr(self, nome)()  # BUG: an f-string is a string: a substring test
        return None
