"""llm-openai-no-max-tokens-py -- nothing here may fire.

Every spelling of the cap, and a call whose arguments come from a dict the
rule cannot see into (vanna's `create(**payload, stream=False)`: measured).
"""


def com_max_tokens(client, mensagens):
    return client.chat.completions.create(model="gpt-4o", messages=mensagens, max_tokens=512)


def com_max_completion_tokens(client, mensagens):
    return client.chat.completions.create(model="o3", messages=mensagens, max_completion_tokens=2048)


def responses_com_limite(client, entrada):
    return client.responses.create(model="gpt-4o", input=entrada, max_output_tokens=1024)


def por_parametros(client, payload):
    return client.chat.completions.create(**payload, stream=False)
