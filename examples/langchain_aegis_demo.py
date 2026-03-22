"""Demo: langchain-aegis standalone integration package.

Shows how to wrap any LangChain tool with Aegis governance using
the `langchain-aegis` package — one function call, zero boilerplate.

Run:
    pip install langchain-aegis
    python examples/langchain_aegis_demo.py
"""

from __future__ import annotations

from langchain_core.tools import BaseTool

from langchain_aegis import govern_tool, govern_tools


# -- Fake tools (replace with your real LangChain tools) -------------------

class WebSearchTool(BaseTool):
    name: str = "web_search"
    description: str = "Search the web for information"

    def _run(self, query: str = "") -> str:
        return f"Results for: {query}"


class DeleteRecordsTool(BaseTool):
    name: str = "delete_records"
    description: str = "Delete records from the database"

    def _run(self, record_id: str = "") -> str:
        return f"Deleted record {record_id}"


class SendEmailTool(BaseTool):
    name: str = "send_email"
    description: str = "Send an email to a recipient"

    def _run(self, to: str = "", body: str = "") -> str:
        return f"Email sent to {to}"


# -- Policy (inline dict — no YAML file needed) ---------------------------

POLICY = {
    "version": "1",
    "defaults": {"risk_level": "low", "approval": "auto"},
    "rules": [
        {
            "name": "block_delete",
            "match": {"type": "delete_*"},
            "risk_level": "critical",
            "approval": "block",
        },
        {
            "name": "review_email",
            "match": {"type": "send_*"},
            "risk_level": "high",
            "approval": "approve",
        },
    ],
}


def main() -> None:
    # Wrap all tools at once — one line
    tools = govern_tools(
        [WebSearchTool(), DeleteRecordsTool(), SendEmailTool()],
        policy=POLICY,
    )

    print("=== langchain-aegis governance demo ===\n")

    for tool in tools:
        result = tool.invoke({"query": "test"} if tool.name == "web_search" else {})
        status = "BLOCKED" if "[BLOCKED" in str(result) else "ALLOWED"
        print(f"  {tool.name:20s} -> {status:8s} | {result}")

    print("\n--- Single tool wrapping ---\n")

    # Or wrap a single tool
    governed_search = govern_tool(WebSearchTool(), policy=POLICY)
    print(f"  {governed_search.invoke({'query': 'AI governance'})}")


if __name__ == "__main__":
    main()
