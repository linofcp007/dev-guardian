"""llm-tool-name-dispatch-py -- nothing here may fire: each is an allowlist.

The two guard shapes the rule's sanitizers recognise, and the dict lookup the
message prescribes (not a sink at all).
"""

FERRAMENTAS = {"meteorologia", "calendario"}


class Ferramentas:
    def despachar_se_permitida(self, resp):
        nome = resp.choices[0].message.tool_calls[0].function.name
        if nome in FERRAMENTAS:
            return getattr(self, nome)()
        return None

    def despachar_com_saida(self, resp):
        nome = resp.choices[0].message.tool_calls[0].function.name
        if nome not in FERRAMENTAS:
            raise ValueError(f"ferramenta desconhecida: {nome}")
        return getattr(self, nome)()


TABELA = {"meteorologia": lambda: "sol", "calendario": lambda: "segunda"}


def despachar_por_tabela(resp):
    return TABELA[resp.choices[0].message.tool_calls[0].function.name]()
