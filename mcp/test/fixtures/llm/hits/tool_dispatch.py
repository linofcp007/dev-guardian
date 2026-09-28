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
