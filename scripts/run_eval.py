#!/usr/bin/env python3
"""
CLI Script to execute the MCP Server Security Audit and Benchmark.
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evals.mcp_eval import MCPEvalSuite, print_mcp_eval_table


def main():
    print("Executing MCP Second Brain Security Audit and Retrieval Suite...")
    suite = MCPEvalSuite()
    rep = suite.run_full_suite()
    print(print_mcp_eval_table(rep))


if __name__ == "__main__":
    main()
