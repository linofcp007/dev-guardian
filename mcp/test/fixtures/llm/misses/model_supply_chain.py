"""llm-trust-remote-code and llm-torch-load-pickle -- nothing here may fire.

The fixes the messages prescribe, and the false-positive class measured on
the corpus (h2oGPT's allowlist of loader keys).
"""

import torch
from safetensors.torch import load_file
from transformers import AutoModelForCausalLM


def carregar_fixado(model_id):
    # Remote code pinned to a commit: what runs is what was reviewed.
    return AutoModelForCausalLM.from_pretrained(model_id, trust_remote_code=True, revision="0f3c1a2b4d5e6f708192a3b4c5d6e7f8091a2b3c")


def carregar_sem_codigo(model_id, args):
    AutoModelForCausalLM.from_pretrained(model_id, trust_remote_code=False)
    return AutoModelForCausalLM.from_pretrained(model_id, trust_remote_code=args.trust_remote_code)


def chaves_permitidas(model_kwargs):
    # Measured (h2oGPT): a dict of the loader keys that are ALLOWED, not a load.
    permitidas = dict(max_new_tokens=None, trust_remote_code=True, fuse_layers=True)
    return {k: v for k, v in model_kwargs.items() if k in permitidas}


def pesos(caminho):
    return torch.load(caminho, weights_only=True)


def pesos_safetensors(caminho):
    return load_file(caminho)
