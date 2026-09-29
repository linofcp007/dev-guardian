"""llm-output-to-interpreter-py -- nothing here may fire.

Each function is either a false-positive class measured on the corpus, the
near-miss one of the rule's regexes exists to exclude, or a fix the rule's
message prescribes.
"""

import ast
import asyncio
import json
import subprocess


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


def commit_message(resp):
    # Review of the pack, I-2: an AI commit-message tool. The model's text is an
    # ARGUMENT in an argv list — no shell parses it, and the program is fixed.
    subprocess.run(["git", "commit", "-m", resp.choices[0].message.content], check=True)
    subprocess.run(["say", resp.choices[0].message.content])


async def commit_message_async(resp):
    await asyncio.create_subprocess_exec("git", "commit", "-m", resp.choices[0].message.content)


def script_argument(resp):
    # Only `-c`/`-e` make an interpreter run the NEXT argument; here the model's
    # text is an argument of a fixed script.
    subprocess.run(["bash", "./notificar.sh", resp.choices[0].message.content])


def grep_pattern(resp):
    # `-e` after a program that is not an interpreter is just an option value.
    subprocess.run(["grep", "-e", resp.choices[0].message.content, "registo.txt"])


class Agente:
    # Review of the pack, M-4: a tool REGISTRY given the model's tool call is
    # dispatch, not SQL; `.execute` is SQL on a cursor, connection, session or
    # engine.
    def __init__(self, tool):
        self.tool = tool

    async def passo(self, tc):
        return await self.tool.execute(json.loads(tc.function.arguments))


class Cadeias:
    # Review of the pack, M-5: `supply_chain`, `user_agent` end in a model word
    # but are not models.
    def __init__(self, supply_chain, user_agent):
        self.supply_chain = supply_chain
        self.user_agent = user_agent

    def configurar(self):
        eval(self.supply_chain.get_config())
        return eval(self.user_agent.lower())


def sklearn_predict(model, linhas):
    # `model` counts only with a LangChain runnable method (invoke/stream/batch).
    return eval(str(model.predict(linhas)))


def lambda_invoke(lambda_client):
    # boto3's Lambda `invoke` returns a FUNCTION's output: `invoke` counts only
    # on a receiver named `model` or `chat` (and the model words above).
    resposta = lambda_client.invoke(FunctionName="relatorio")
    return exec(resposta["Payload"].read())


def bytes_decode(caminho):
    # `.decode()` is model text only on a tokenizer or processor; these are the
    # bytes of a local file.
    with open(caminho, "rb") as f:
        exec(f.read().decode("utf-8"))


def chat_template(tokenizer, mensagens):
    # A tokenizer's OTHER methods return the prompt, not the model's text.
    return eval(tokenizer.apply_chat_template(mensagens, tokenize=False))
