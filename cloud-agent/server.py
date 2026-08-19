
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent.memory import load_memory, save_turn, build_memory_context
from agent.watcher import GraphWatcher
from agent.agent import run_agent

app = FastAPI()

# Start the graph watcher once at server startup
_watcher = GraphWatcher()
_watcher.start()


@app.get("/ping")
def ping():
    return {"status": "Healthy"}


@app.post("/invocations")
async def invoke(request: Request):
    body = await request.json()

    # Accept {"prompt": "..."} or {"input": {"prompt": "..."}}
    prompt = (
        body.get("prompt")
        or (body.get("input") or {}).get("prompt")
        or ""
    )

    if not prompt:
        return JSONResponse({"error": "Missing 'prompt' field"}, status_code=400)

    history = load_memory()
    memory_context = build_memory_context(history)

    answer = run_agent(prompt, verbose=False, memory_context=memory_context)

    save_turn(prompt, answer)

    return {"output": {"message": answer}}
