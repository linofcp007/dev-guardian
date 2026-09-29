"""llm-trust-remote-code and the two torch.load rules -- every `# BUG` line fires exactly once.

`trust_remote_code=True` runs Python shipped in the model (or dataset)
repository at load time; unless the revision is pinned to a commit, the
code that runs is whatever the repository holds on that day. `torch.load`
unpickles when `weights_only` is False — always with `weights_only=False`
(llm-torch-load-weights-only-false), and by default before torch 2.6 when
the argument is absent (llm-torch-load-no-weights-only).
"""

import torch
from datasets import load_dataset
from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer


def carregar(model_id):
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)  # BUG: remote code, unpinned
    modelo = AutoModelForCausalLM.from_pretrained(model_id, revision="main", trust_remote_code=True)  # BUG: a BRANCH is not a pin
    return tokenizer, modelo


def carregar_por_tag(model_id):
    return AutoConfig.from_pretrained(model_id, revision="v1.0", trust_remote_code=True)  # BUG: a tag can be moved


def carregar_com_loader(model_loader, base_model):
    return model_loader(base_model, load_in_8bit=True, trust_remote_code=True)  # BUG: from_pretrained behind a variable


def dataset_script():
    return load_dataset("codeparrot/apps", trust_remote_code=True)  # BUG: a dataset's loading script is code too


def carregar_com_kwargs(model_id):
    opcoes = dict(device_map="auto", trust_remote_code=True)  # excluded: a dict(...) of kwargs is not a load (the call below is)
    return AutoModelForCausalLM.from_pretrained(model_id, **opcoes)  # BUG: the flag carried by a dict(...) of kwargs


def carregar_com_dicionario(model_id):
    model_kwargs = {"torch_dtype": "auto", "trust_remote_code": True}
    return AutoModelForCausalLM.from_pretrained(model_id, **model_kwargs)  # BUG: the flag carried by a dict literal


def checkpoint(caminho):
    return torch.load(caminho)  # BUG: pickle by default before torch 2.6 (LOW)


def checkpoint_cpu(caminho):
    return torch.load(caminho, map_location="cpu")  # BUG: map_location changes nothing (LOW)


def checkpoint_explicito(caminho):
    return torch.load(caminho, weights_only=False)  # BUG: pickle explicitly enabled, on any torch (WARNING; excluded for the LOW rule: the argument is there)
