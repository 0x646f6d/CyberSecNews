"""CyberSecNews — daily cybersecurity news aggregator.

Fetches security news from configured sources, keeps only zero/n-day
vulnerabilities and red-team tradecraft, deduplicates against a persistent
store, summarizes new items with a small LLM, and reports via ntfy.sh.
"""

__version__ = "0.1.0"
