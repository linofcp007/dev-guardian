"""llm-output-to-interpreter-py -- every `# BUG` line fires the rule exactly once.

The first block reaches the SAME sink (`exec`) from each source the rule
knows, one source per function, and no function is reachable from two of
them: removing any one source branch must lose exactly its own line. The
second block reaches each sink from one source (a response object passed in
as a parameter, the most common shape in real code).
"""

import asyncio
import json
import os
import subprocess

import litellm
import openai
import pandas as pd
from langchain_experimental.utilities import PythonREPL
from sqlalchemy import text


# ---------------------------------------------------------------- sources

def openai_stream(client, pergunta):
    stream = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": pergunta}], max_tokens=512, stream=True)  # excluded: capped (llm-openai-no-max-tokens-py)
    for chunk in stream:
        exec(chunk.choices[0].delta.content)  # BUG: an OpenAI call's streamed chunk


def openai_responses_stream(client, pergunta):
    for event in client.responses.create(model="gpt-4o", input=pergunta, max_output_tokens=512, stream=True):  # excluded: capped (llm-openai-no-max-tokens-py)
        exec(event.delta)  # BUG: a Responses API stream event


def openai_legacy(pergunta):
    r = openai.ChatCompletion.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": pergunta}])
    exec(r.choices[0].message["content"])  # BUG: the pre-1.0 SDK


def anthropic_blocks(client, pergunta):
    msg = client.messages.create(model="claude-sonnet-4-5", max_tokens=1024, messages=[{"role": "user", "content": pergunta}])
    for block in msg.content:
        exec(block.text)  # BUG: an Anthropic message's text blocks


def litellm_call(pergunta):
    r = litellm.completion(model="gpt-4o", messages=[{"role": "user", "content": pergunta}])
    exec(r.choices[0].message["content"])  # BUG: LiteLLM


def sagemaker_endpoint(runtime, corpo):
    resp = runtime.invoke_endpoint(EndpointName="llm", Body=json.dumps(corpo), ContentType="application/json")
    exec(resp["Body"].read().decode("utf-8"))  # BUG: a SageMaker model endpoint


def bedrock_invoke(bedrock, corpo):
    resp = bedrock.invoke_model(modelId="anthropic.claude-v2", body=json.dumps(corpo))
    exec(json.loads(resp["body"].read())["completion"])  # BUG: Bedrock invoke_model


def bedrock_converse(bedrock, mensagens):
    resp = bedrock.converse(modelId="amazon.nova-pro-v1:0", messages=mensagens)
    exec(resp["output"]["message"]["content"][0]["text"])  # BUG: Bedrock converse


class Planeador:
    def __init__(self, llm):
        self.llm = llm

    async def planear(self, contexto):
        conteudo = await self.llm.aask(contexto)
        return eval(conteudo)  # BUG: any method of an object NAMED like a model (MetaGPT's aask)


def legacy_llm_call(llm, pergunta):
    resposta = llm(pergunta)
    exec(resposta)  # BUG: a model object called directly (LangChain's old `llm(prompt)`)


def from_parameter(resp):
    exec(resp.choices[0].message.content)  # BUG: a chat completion handed in by the caller


def legacy_text(resp):
    exec(resp.choices[0].text)  # BUG: a legacy completion's text


def dict_shape(resp):
    exec(resp["choices"][0]["message"]["content"])  # BUG: the same response read as a dict


def responses_output(resp):
    exec(resp.output_text)  # BUG: the Responses API's output_text


def anthropic_content(msg):
    exec(msg.content[0].text)  # BUG: an Anthropic message's first block


def tool_arguments(call):
    args = json.loads(call.function.arguments)
    exec(args["codigo"])  # BUG: tool-call arguments are written by the model


def handle(assistant_reply):
    return eval(assistant_reply)  # BUG: a value NAMED as a model's reply (SuperAGI's eval(assistant_reply))


# ------------------------------------------------------------------ sinks

def to_os_system(resp):
    os.system(resp.choices[0].message.content)  # BUG: a shell


def to_os_popen(resp):
    return os.popen(resp.choices[0].message.content).read()  # BUG: a shell, with the output read back


def to_subprocess(resp):
    subprocess.run(resp.choices[0].message.content, shell=True)  # BUG: subprocess


async def to_asyncio_shell(resp):
    await asyncio.create_subprocess_shell(resp.choices[0].message.content)  # BUG: an asyncio shell


def to_repl(resp):
    repl = PythonREPL()
    return repl.run(resp.choices[0].message.content)  # BUG: a Python REPL wrapper (LangChain's PAL chain)


def to_bash_process(bash_process, resp):
    return bash_process.run(resp.choices[0].message.content)  # BUG: a bash wrapper (LangChain's LLMBashChain)


def to_cursor(cursor, resp):
    cursor.execute(resp.choices[0].message.content)  # BUG: SQL the model wrote


def to_executemany(cursor, resp, linhas):
    cursor.executemany(resp.choices[0].message.content, linhas)  # BUG: SQL, many rows


def to_executescript(conn, resp):
    conn.executescript(resp.choices[0].message.content)  # BUG: a whole SQL script


def to_sqlalchemy_text(resp):
    consulta = text(resp.choices[0].message.content)  # BUG: SQLAlchemy text() builds an executable statement
    return consulta


def to_read_sql(engine, resp):
    return pd.read_sql(resp.choices[0].message.content, engine)  # BUG: pandas read_sql


def to_read_sql_query(engine, resp):
    return pd.read_sql_query(resp.choices[0].message.content, engine)  # BUG: pandas read_sql_query


def to_sql_database(database, resp):
    return database.run(resp.choices[0].message.content)  # BUG: LangChain's SQLDatabase.run
