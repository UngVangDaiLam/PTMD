"""Client Ollama qua HTTP API (`/api/chat`), `format="json"`, `temperature=0`.

Chỉ gửi tin nhắn văn bản (đặc trưng đã trích), không bao giờ gửi file mẫu.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

import requests


@dataclass
class LLMReply:
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLM(Protocol):
    model: str

    def chat(self, messages: list[dict]) -> LLMReply: ...


class OllamaClient:
    def __init__(self, model: str = "qwen2.5:7b", host: str | None = None, temperature: float = 0,
                 num_ctx: int = 8192, timeout_s: int = 600, json_mode: bool = True) -> None:
        self.model = model
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.timeout_s = timeout_s
        self.json_mode = json_mode

    def chat(self, messages: list[dict]) -> LLMReply:
        body: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature, "num_ctx": self.num_ctx, "seed": 0},
        }
        if self.json_mode:
            body["format"] = "json"
        r = requests.post(f"{self.host}/api/chat", json=body, timeout=self.timeout_s)
        r.raise_for_status()
        data = r.json()
        return LLMReply(
            content=data.get("message", {}).get("content", ""),
            prompt_tokens=int(data.get("prompt_eval_count", 0) or 0),
            completion_tokens=int(data.get("eval_count", 0) or 0),
        )

    @classmethod
    def from_config(cls, cfg: dict) -> "OllamaClient":
        llm = cfg.get("llm", {})
        return cls(
            model=llm.get("model", "qwen2.5:7b"),
            host=os.environ.get("OLLAMA_HOST") or llm.get("host"),
            temperature=llm.get("temperature", 0),
            num_ctx=llm.get("num_ctx", 8192),
            json_mode=llm.get("format", "json") == "json",
        )
