"""llm-trust-remote-code and llm-torch-load-pickle -- every `# BUG` line fires exactly once.

`trust_remote_code=True` runs Python shipped in the model (or dataset)
repository at load time; unless the revision is pinned to a commit, the
code that runs is whatever the repository holds on that day. `torch.load`
without `weights_only=True` unpickles, and unpickling runs code.
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


def checkpoint(caminho):
    return torch.load(caminho)  # BUG: pickle enabled by default before torch 2.6


def checkpoint_cpu(caminho):
    return torch.load(caminho, map_location="cpu")  # BUG: map_location changes nothing


def checkpoint_explicito(caminho):
    return torch.load(caminho, weights_only=False)  # BUG: pickle explicitly enabled, on any torch
