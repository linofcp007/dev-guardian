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
import shlex
import subprocess
import sys

import litellm
import openai
import pandas as pd
from langchain_experimental.utilities import PythonREPL
from langchain_openai import ChatOpenAI
from sqlalchemy import text
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline


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


def structured_output(client, pergunta, Plano):
    r = client.beta.chat.completions.parse(model="gpt-4o", messages=[{"role": "user", "content": pergunta}], response_format=Plano, max_completion_tokens=512)  # excluded: capped (llm-openai-no-max-tokens-py)
    exec(r.choices[0].message.parsed.codigo)  # BUG: structured output (chat.completions.parse)


def responses_structured(client, pergunta, Plano):
    r = client.responses.parse(model="gpt-4o", input=pergunta, text_format=Plano, max_output_tokens=512)  # excluded: capped (llm-openai-no-max-tokens-py)
    exec(r.output_parsed.codigo)  # BUG: structured output (responses.parse)


def anthropic_stream(client, pergunta):
    with client.messages.stream(model="claude-sonnet-4-5", max_tokens=1024, messages=[{"role": "user", "content": pergunta}]) as stream:
        for texto in stream.text_stream:
            exec(texto)  # BUG: an Anthropic message stream


def hf_inference_text(hf, pergunta):
    exec(hf.text_generation(pergunta, max_new_tokens=200))  # BUG: Hugging Face InferenceClient.text_generation


def hf_inference_chat(hf, mensagens):
    for chunk in hf.chat_completion(mensagens, max_tokens=200, stream=True):
        exec(chunk.choices[0].delta.content)  # BUG: Hugging Face InferenceClient.chat_completion


def hf_pipeline(pergunta):
    gerador = pipeline("text-generation", model="gpt2")
    saida = gerador(pergunta)
    exec(saida[0]["generated_text"])  # BUG: a transformers pipeline, called


def hf_generate(model_id, pergunta):
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    modelo = AutoModelForCausalLM.from_pretrained(model_id)
    ids = modelo.generate(**tokenizer(pergunta, return_tensors="pt"))
    exec(tokenizer.decode(ids[0], skip_special_tokens=True))  # BUG: generate + decode: the decoded text is the model's


def langchain_model(pergunta):
    model = ChatOpenAI(model="gpt-4o", max_tokens=512)
    exec(model.invoke(pergunta).content)  # BUG: a LangChain chat model held in `model`


# ------------------------------------------------------------------ sinks

def to_os_system(resp):
    os.system(resp.choices[0].message.content)  # BUG: a shell


def to_os_popen(resp):
    return os.popen(resp.choices[0].message.content).read()  # BUG: a shell, with the output read back


def to_subprocess(resp):
    subprocess.run(resp.choices[0].message.content, shell=True)  # BUG: subprocess with shell=True


def to_subprocess_program(resp):
    subprocess.run([resp.choices[0].message.content, "--help"])  # BUG: the model picks the PROGRAM (argv[0])


def to_subprocess_sh_c(resp):
    subprocess.check_output(["bash", "-c", resp.choices[0].message.content])  # BUG: bash -c runs its argument as a script


def to_subprocess_python_c(resp):
    subprocess.run(["python3", "-c", resp.choices[0].message.content])  # BUG: python -c runs its argument as code


def to_subprocess_shlex(resp):
    subprocess.run(shlex.split(resp.choices[0].message.content))  # BUG: program and arguments both from the model


def to_subprocess_getoutput(resp):
    return subprocess.getoutput(resp.choices[0].message.content)  # BUG: getoutput always runs a shell


async def to_asyncio_shell(resp):
    await asyncio.create_subprocess_shell(resp.choices[0].message.content)  # BUG: an asyncio shell


async def to_asyncio_exec(resp):
    await asyncio.create_subprocess_exec(resp.choices[0].message.content, "--help")  # BUG: the model picks the program


async def to_asyncio_exec_bash(resp):
    await asyncio.create_subprocess_exec("bash", "-c", resp.choices[0].message.content)  # BUG: bash runs its argument


def interpreters_and_wrappers(resp):
    # Review of the pack, round 2 (I-B): the model's text anywhere in the argv of
    # an interpreter, a shell or a wrapper — whatever the options in between.
    t = resp.choices[0].message.content
    subprocess.run(["sh", "-lc", t])  # BUG: sh -lc
    subprocess.run(["bash", "-e", "-c", t])  # BUG: an option before -c
    subprocess.run(["bash", "--norc", "-c", t])  # BUG: a long option before -c
    subprocess.run([sys.executable, "-c", t])  # BUG: the running interpreter, by variable
    subprocess.run(["python3", "-m", t])  # BUG: python -m runs the module the model names
    subprocess.run(["env", t])  # BUG: env runs its argument
    subprocess.run(["/usr/bin/env", "bash", "-c", t])  # BUG: env, then bash
    subprocess.run(["timeout", "10", t])  # BUG: timeout runs its argument
    subprocess.run(["xargs", t])  # BUG: xargs runs its argument
    subprocess.run(["powershell", "-Command", t])  # BUG: PowerShell
    subprocess.run(["cmd", "/c", t])  # BUG: cmd /c
    subprocess.run(["bash", "./notificar.sh", t])  # BUG: an interpreter's argument may be code: the rule cannot tell a script from an option
    subprocess.run(["awk", t])  # BUG: an awk program is code (its system() runs a shell)
    subprocess.run(["watch", "-n", "5", t])  # BUG: watch hands its command to sh -c
    subprocess.run(["pythonw", "-c", t])  # BUG: the windowless Python


def container_and_find_wrappers(resp):
    # Review of the pack, round 3: programs that run a command they are handed —
    # in a container, a pod, another namespace, or per file found.
    t = resp.choices[0].message.content
    subprocess.run(["docker", "run", "--rm", "alpine", "sh", "-c", t])  # BUG: docker run … sh -c
    subprocess.run(["podman", "exec", "db", t])  # BUG: podman exec runs its argument
    subprocess.run(["kubectl", "exec", "web-0", "--", "sh", "-c", t])  # BUG: kubectl exec … sh -c
    subprocess.run(["find", ".", "-name", "*.log", "-exec", t, ";"])  # BUG: find -exec runs its argument
    subprocess.run(["nsenter", "-t", "1", "-m", t])  # BUG: nsenter runs its argument in another namespace


def fixed_program_with_a_shell(resp, usar_shell):
    t = resp.choices[0].message.content
    subprocess.run(["git", "commit", "-m", t], shell=True)  # BUG: with a shell the list is a command line
    subprocess.run(["git", "commit", "-m", t], shell=usar_shell)  # BUG: a shell the rule cannot rule out
    args = ["git", "commit", "-m", t]
    subprocess.run(args, shell=True)  # BUG: the same, the list in a variable


def interpreter_list_in_a_variable(resp):
    cmd = ["bash", "-c", resp.choices[0].message.content]
    subprocess.run(cmd)  # BUG: an interpreter's argv, built first


def to_os_exec(resp):
    os.execl("/bin/sh", "sh", "-c", resp.choices[0].message.content)  # BUG: os.exec* of a shell


def to_os_exec_named(resp):
    # argv[0] is only the name the process shows; the program is the first argument.
    os.execl("/bin/bash", "relatorio", "-c", resp.choices[0].message.content)  # BUG: os.exec* of bash, whatever argv[0] says


def to_os_exec_program(resp):
    os.execv(resp.choices[0].message.content, ["--help"])  # BUG: os.exec* of the model's program


def to_os_spawn(resp):
    os.spawnlp(os.P_WAIT, "bash", "bash", "-c", resp.choices[0].message.content)  # BUG: os.spawn* of a shell


def to_repl(resp):
    repl = PythonREPL()
    return repl.run(resp.choices[0].message.content)  # BUG: a Python REPL wrapper (LangChain's PAL chain)


def to_bash_process(bash_process, resp):
    return bash_process.run(resp.choices[0].message.content)  # BUG: a bash wrapper (LangChain's LLMBashChain)


def to_cursor(cursor, resp):
    cursor.execute(resp.choices[0].message.content)  # BUG: SQL the model wrote


def to_connection_cursor(conn, resp):
    conn.cursor().execute(resp.choices[0].message.content)  # BUG: a cursor made inline


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
