"""llm-openai-no-max-tokens-py -- every `# BUG` line fires exactly once.

An OpenAI chat or Responses call with no cap on the tokens it may generate.
"""


def conversar(client, mensagens):
    return client.chat.completions.create(model="gpt-4o", messages=mensagens)  # BUG: no cap


def conversar_em_stream(client, mensagens):
    return client.chat.completions.create(model="gpt-4o", messages=mensagens, stream=True, temperature=0)  # BUG: streaming changes nothing


def responder(client, entrada):
    return client.responses.create(model="gpt-4o", input=entrada)  # BUG: the Responses API, no cap
