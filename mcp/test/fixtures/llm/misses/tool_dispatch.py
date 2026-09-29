"""llm-tool-name-dispatch-py -- nothing here may fire: each is an allowlist.

The guard shapes the rule's sanitizers recognise — the THEN block of
`if nome in PERMITIDAS:`, and the rest of the function after
`if nome not in PERMITIDAS:` that leaves by raise, return or continue — and
the dict lookup the message prescribes (not a sink at all).
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
            logger.warning("ferramenta desconhecida: %s", nome)
            raise ValueError(f"ferramenta desconhecida: {nome}")
        return getattr(self, nome)()

    def despachar_ou_nada(self, resp):
        nome = resp.choices[0].message.tool_calls[0].function.name
        if nome not in FERRAMENTAS:
            return {"erro": f"ferramenta desconhecida: {nome}"}
        return getattr(self, nome)()

    def despachar_todas(self, resp):
        for chamada in resp.choices[0].message.tool_calls:
            nome = chamada.function.name
            if nome not in FERRAMENTAS:
                continue
            getattr(self, nome)()


    def despachar_elif(self, resp):
        nome = resp.choices[0].message.tool_calls[0].function.name
        if not nome:
            raise ValueError("sem nome")
        elif nome not in FERRAMENTAS:
            raise ValueError(f"ferramenta desconhecida: {nome}")
        return getattr(self, nome)()

    def despachar_ate_parar(self, resp):
        for chamada in resp.choices[0].message.tool_calls:
            nome = chamada.function.name
            if nome not in FERRAMENTAS:
                break
            getattr(self, nome)()

    def despachar_sem_valor(self, resp):
        nome = resp.choices[0].message.tool_calls[0].function.name
        if nome not in FERRAMENTAS:
            return
        getattr(self, nome)()


TABELA = {"meteorologia": lambda: "sol", "calendario": lambda: "segunda"}


def despachar_por_tabela(resp):
    return TABELA[resp.choices[0].message.tool_calls[0].function.name]()
