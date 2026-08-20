import json
import os
import re
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from openai import OpenAI, RateLimitError, BadRequestError

from agent.prompts import SYSTEM_PROMPT
from agent.definitions import DEFINITIONS, FUNCTIONS


def _make_client():
    provider = os.environ.get("LLM_PROVIDER", "groq").lower()

    if provider == "groq":
        return (
            OpenAI(base_url="https://api.groq.com/openai/v1", api_key=os.environ["GROQ_API_KEY"]),
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
    objects, depth, start = [], 0, -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                try:
                    objects.append(json.loads(text[start: i + 1]))
                except json.JSONDecodeError:
                    pass
                start = -1
    return objects


def _extract_text_tool_calls(content: str) -> list[dict]:
    calls = []

    for match in re.finditer(r"<tool_call>(.*?)(?:</tool_call>|$)", content, re.DOTALL):
        for obj in _extract_json_objects(match.group(1)):
            if "name" in obj:
                calls.append(obj)
    if calls:
        return calls

    for match in re.finditer(r"```(?:\w+)?\s*(.*?)```", content, re.DOTALL):
        for obj in _extract_json_objects(match.group(1)):
            if "name" in obj and ("arguments" in obj or "parameters" in obj):
                calls.append(obj)
    if calls:
        return calls

    for obj in _extract_json_objects(content):
        if "name" in obj and ("arguments" in obj or "parameters" in obj):
            calls.append(obj)

    return calls


_MAX_RESULT_CHARS = 1500


def _dispatch(name: str, args: dict, verbose: bool) -> str:
    if verbose:
        print(f"  [tool] {name}({str(args)[:120]})")
    fn = FUNCTIONS.get(name)
    try:
        result = fn(args) if fn else f"Unknown tool: {name}"
    except Exception as e:
        result = f"Tool error: {e}"
    # Truncate large results to keep token usage under control
    if len(result) > _MAX_RESULT_CHARS:
        result = result[:_MAX_RESULT_CHARS] + f"\n...[truncated, {len(result)} chars total]"
    if verbose:
        preview = result[:300] + "..." if len(result) > 300 else result
        print(f"  [result] {preview}\n")
    return result


def run_agent(
    objective: str,
    context: str = "",
    verbose: bool = True,
) -> str:
    """
    Run the web/pentest agent against a given objective.

    Args:
        objective: Natural-language pentest goal e.g. "Assess 18.132.37.248 for vulnerabilities"
        context:   Optional extra context injected into the system prompt
                   (e.g. findings passed from the cloud-agent orchestrator)
        verbose:   Print tool calls and results
    """
    client, model = _make_client()

    system_content = SYSTEM_PROMPT
    if context:
        system_content += f"\n\n## Context from orchestrator\n{context}"

    # Keep only last N tool exchanges to prevent context overflow
    _MAX_TOOL_EXCHANGES = 4

    def _prune(msgs: list) -> list:
        """Keep system + original user message + last N tool exchanges."""
        head = [m for m in msgs if m.get("role") in ("system", "user")][:2]
        tail = [m for m in msgs if m.get("role") not in ("system",)]
        # Summarise pruned findings as a single injected user message
        if len(tail) > _MAX_TOOL_EXCHANGES * 2 + 1:
            kept = tail[-(_MAX_TOOL_EXCHANGES * 2):]
            pruned = tail[:-(len(kept))]
            summary_lines = []
            for m in pruned:
                if isinstance(m, dict) and m.get("role") == "tool":
                    summary_lines.append(m["content"][:300])
            summary = "\n---\n".join(summary_lines)
            head.append({
                "role": "user",
                "content": f"[Previous tool findings summary]\n{summary}\n\nContinue the pentest.",
            })
            return head + kept
        return msgs

    messages = [
        {"role": "system", "content": system_content},
        {"role": "user", "content": objective},
    ]

    while True:
        messages = _prune(messages)

        for attempt in range(6):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=DEFINITIONS,
                    tool_choice="auto",
                )
                break
            except RateLimitError:
                wait = min(2 ** attempt * 5, 60)
                print(f"  [rate limit] waiting {wait}s before retry ({attempt+1}/6)...")
                time.sleep(wait)
            except (BadRequestError, Exception) as e:
                err = str(e)
                if "tool_use_failed" in err or "tool call validation" in err.lower():
                    print(f"  [bad tool call] recovering: {err[:120]}")
                    while messages and messages[-1].get("role") in ("tool", "assistant"):
                        messages.pop()
                    messages.append({
                        "role": "user",
                        "content": "Your last tool call was invalid. Only use tools from the provided list. Continue.",
                    })
                    break
                if "413" in err or "Request too large" in err:
                    # Hard prune — drop all but last 2 exchanges
                    print(f"  [context overflow] pruning history hard...")
                    head = messages[:2]
                    tail = messages[-4:]
                    messages = head + tail
                    break
                return f"Error: {e}"
        else:
            return "Error: rate limit retries exhausted."

        choice = response.choices[0]

        if choice.finish_reason == "tool_calls":
            assistant_message = choice.message
            # Serialize pydantic object to plain dict so _prune() can call .get()
            messages.append({
                "role": "assistant",
                "content": assistant_message.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in (assistant_message.tool_calls or [])
                ],
            })
            for tool_call in assistant_message.tool_calls:
                name = tool_call.function.name
                args = json.loads(tool_call.function.arguments)
                result = _dispatch(name, args, verbose)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result,
                })
            continue

        content = choice.message.content or ""
        text_calls = _extract_text_tool_calls(content)
        if text_calls:
            messages.append({"role": "assistant", "content": content})
            for call in text_calls:
                name = call.get("name", "")
                args = call.get("arguments") or call.get("parameters") or {}
                result = _dispatch(name, args, verbose)
                messages.append({
                    "role": "tool",
                    "tool_call_id": str(uuid.uuid4()),
                    "content": result,
                })
            continue

        return content


def main():
    provider = os.environ.get("LLM_PROVIDER", "groq")
    model = os.environ.get("LLM_MODEL", "")
    print(f"Web Pentest Agent  [{provider} / {model}]")
    print("Describe your pentest objective. Type 'exit' to quit.\n")

    while True:
        try:
            objective = input("Objective: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not objective:
            continue
        if objective.lower() in ("exit", "quit"):
            print("Goodbye.")
            break

        print()
        report = run_agent(objective)
        print(f"\n{'='*60}\nREPORT\n{'='*60}\n{report}\n{'='*60}\n")


if __name__ == "__main__":
    main()
