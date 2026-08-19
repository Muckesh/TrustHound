import json
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from openai import OpenAI

from agent.prompts import SYSTEM_PROMPT
from agent.tools import DEFINITIONS, FUNCTIONS
from agent.memory import load_memory, save_turn, build_memory_context
from agent.watcher import GraphWatcher


def _make_client():
    provider = os.environ.get("LLM_PROVIDER", "groq").lower()

    if provider == "groq":
        return (
            OpenAI(
                base_url="https://api.groq.com/openai/v1",
                api_key=os.environ["GROQ_API_KEY"],
            ),
            os.environ.get("LLM_MODEL", "llama-3.3-70b-versatile"),
        )

    if provider == "ollama":
        api_key = os.environ.get("OLLAMA_API_KEY") or "ollama"
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        return (
            OpenAI(base_url=base_url, api_key=api_key),
            os.environ.get("LLM_MODEL", "qwen2.5:7b"),
        )

    raise ValueError(f"Unknown LLM_PROVIDER '{provider}'. Use 'groq' or 'ollama'.")


def _extract_json_objects(text: str) -> list[dict]:
    """Extract all top-level JSON objects from text using brace matching."""
    objects = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                try:
                    objects.append(json.loads(text[start : i + 1]))
                except json.JSONDecodeError:
                    pass
                start = -1
    return objects


def _extract_text_tool_calls(content: str) -> list[dict]:
    """
    Local models (qwen2.5, llama3.1) sometimes emit tool calls as raw text
    instead of structured tool_calls. Handles these formats:
      <tool_call>{...}</tool_call>
      ```python / ```json  {...}  ```
      bare JSON: {"name": "...", "arguments": {...}}
    """
    calls = []

    # Format 1: <tool_call>{...}</tool_call>  (with or without closing tag)
    for match in re.finditer(r"<tool_call>(.*?)(?:</tool_call>|$)", content, re.DOTALL):
        for obj in _extract_json_objects(match.group(1)):
            if "name" in obj:
                calls.append(obj)

    if calls:
        return calls

    # Format 2: JSON inside a code block ```python / ```json / ``` ... ```
    for match in re.finditer(r"```(?:\w+)?\s*(.*?)```", content, re.DOTALL):
        for obj in _extract_json_objects(match.group(1)):
            if "name" in obj and ("arguments" in obj or "parameters" in obj):
                calls.append(obj)

    if calls:
        return calls

    # Format 3: any JSON object in the text with "name" + "arguments"/"parameters"
    for obj in _extract_json_objects(content):
        if "name" in obj and ("arguments" in obj or "parameters" in obj):
            calls.append(obj)

    return calls


def _dispatch_tool(name: str, args: dict, verbose: bool) -> str:
    if verbose:
        print(f"  [tool] {name}({str(args)[:120]})")
    fn = FUNCTIONS.get(name)
    try:
        result = fn(args) if fn else f"Unknown tool: {name}"
    except Exception as e:
        result = f"Tool error: {e}"
    if verbose:
        preview = result[:200] + "..." if len(result) > 200 else result
        print(f"  [result] {preview}\n")
    return result


def run_agent(question: str, verbose: bool = True, memory_context: str = "") -> str:
    client, model = _make_client()

    system_content = SYSTEM_PROMPT
    if memory_context:
        system_content = system_content + "\n\n" + memory_context

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": question},
    ]

    while True:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=DEFINITIONS,
            tool_choice="auto",
        )

        choice = response.choices[0]

        # --- Structured tool calling (preferred path) ---
        if choice.finish_reason == "tool_calls":
            assistant_message = choice.message
            messages.append(assistant_message)

            for tool_call in assistant_message.tool_calls:
                name = tool_call.function.name
                args = json.loads(tool_call.function.arguments)
                result = _dispatch_tool(name, args, verbose)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result,
                })
            continue

        # --- Text output: check for embedded tool calls (fallback for local models) ---
        content = choice.message.content or ""
        text_calls = _extract_text_tool_calls(content)

        if text_calls:
            messages.append({"role": "assistant", "content": content})
            for call in text_calls:
                name = call.get("name", "")
                args = call.get("arguments") or call.get("parameters") or {}
                result = _dispatch_tool(name, args, verbose)
                messages.append({
                    "role": "tool",
                    "tool_call_id": str(uuid.uuid4()),
                    "content": result,
                })
            continue

        # --- Final answer ---
        return content


def main():
    provider = os.environ.get("LLM_PROVIDER", "groq")
    model = os.environ.get("LLM_MODEL", "")
    print(f"Cloud Security Agent  [{provider} / {model}]")
    print("Type your question. Press Ctrl+C or type 'exit' to quit.\n")

    watcher = GraphWatcher()
    watcher.start()
    print()

    history = load_memory()
    if history:
        print(f"[Memory] Loaded {len(history)} previous session(s).\n")
    memory_context = build_memory_context(history)

    while True:
        try:
            question = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not question:
            continue

        if question.lower() in ("exit", "quit"):
            print("Goodbye.")
            break

        print()
        answer = run_agent(question, memory_context=memory_context)
        print(f"\nAgent:\n{answer}\n")
        print("─" * 60 + "\n")

        save_turn(question, answer)
        history = load_memory()
        memory_context = build_memory_context(history)


if __name__ == "__main__":
    main()
