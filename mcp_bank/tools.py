"""MCP tools exposed to the client: account balance and transaction log.

Amounts are converted to the caller's currency using ECB rates published by
frankfurter.app.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Annotated

import requests
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from .banking.client import get_details

_SYMBOLS = {"$": "USD", "£": "GBP", "€": "EUR"}
_SUPPORTED = frozenset(_SYMBOLS.values())

# Card number and trailing "dd/mm" that the bank staples onto every label.
_NOISE = re.compile(r"X8969\s*|\s*\d{2}/\d{2}$")

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DEFAULT_WINDOW_DAYS = 120
_RATE_LOOKBACK_DAYS = 7


def normalise_currency(code: str) -> str:
    """Turn a symbol or ISO code into a supported three-letter ISO code."""
    code = code.strip()
    if code in _SUPPORTED:
        return code
    try:
        return _SYMBOLS[code]
    except KeyError:
        raise ValueError(f"Unsupported currency: {code!r}") from None


def _check_date(date_str: str) -> None:
    if not _DATE_RE.match(date_str):
        raise ValueError(f"Invalid date {date_str!r}, expected YYYY-MM-DD.")


def get_exchange_rates(
    start_date: str, end_date: str, from_currency: str, to_currency: str
) -> dict:
    """Daily rates published between two dates, keyed by date."""
    for date_str in (start_date, end_date):
        _check_date(date_str)
    from_currency, to_currency = (
        normalise_currency(c) for c in (from_currency, to_currency)
    )

    url = f"https://api.frankfurter.app/{start_date}..{end_date}"
    response = requests.get(
        url, params={"from": from_currency, "to": to_currency}, timeout=30
    )
    response.raise_for_status()
    return response.json()["rates"]


@lru_cache(maxsize=128)
def get_latest_rate(target_date: str, from_currency: str, to_currency: str) -> float:
    """Rate for ``target_date``, falling back to the most recent earlier date.

    The ECB publishes nothing on weekends and holidays, so the requested date
    itself is often missing. Cached: converting a transaction log otherwise
    re-queries the same rate once per line.
    """
    window_start = (
        datetime.fromisoformat(target_date) - timedelta(days=_RATE_LOOKBACK_DAYS)
    ).strftime("%Y-%m-%d")
    rates = get_exchange_rates(window_start, target_date, from_currency, to_currency)

    available = [d for d in rates if d <= target_date]
    if not available:
        raise ToolError(
            f"No exchange rate for {from_currency}->{to_currency} "
            f"between {window_start} and {target_date}"
        )
    return rates[max(available)][normalise_currency(to_currency)]


def _convert(amount: float, from_currency: str, to_currency: str) -> float:
    """Convert using yesterday's rate, the most recent one reliably published."""
    if from_currency == to_currency:
        return amount
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    return amount * get_latest_rate(yesterday, from_currency, to_currency)


class CheckingAccount(BaseModel):
    account_balance: float = Field(
        description="The checking account's closing booked balance"
    )
    account_currency: str = Field(
        description="Three-letter ISO currency code (EUR, USD or GBP)"
    )


class Transaction(BaseModel):
    transaction_date: str = Field(description="Date of the transaction, YYYY-MM-DD")
    transaction_amount: float = Field(
        description="Signed amount: positive for credits, negative for debits"
    )
    balance_after_transaction: float = Field(
        description="Account balance once this transaction had settled"
    )
    balance_doc: str = Field(
        description="Counterparty: store, website, sender or organisation"
    )


class TransactionsList(BaseModel):
    transactions: list[Transaction] = Field(description="Transactions, newest first")
    timeframe_start: str = Field(description="Start of the timeframe, YYYY-MM-DD")
    timeframe_end: str = Field(description="End of the timeframe, YYYY-MM-DD")
    currency: str = Field(
        description="Three-letter ISO currency code shared by every amount"
    )


def get_balance(expected_currency: str = "EUR") -> float:
    """Current booked balance, converted to ``expected_currency``."""
    expected_currency = normalise_currency(expected_currency)
    balance = get_details("balances")["balances"][0]["balance_amount"]
    currency = normalise_currency(balance["currency"])
    return _convert(float(balance["amount"].strip()), currency, expected_currency)


def register(mcp: FastMCP) -> None:
    """Attach the banking tools to a FastMCP server."""

    @mcp.tool()
    def checking_account_balance(expected_currency: str = "EUR") -> CheckingAccount:
        """Get the current balance of the checking account, in a chosen currency."""
        return CheckingAccount(
            account_balance=get_balance(expected_currency),
            account_currency=normalise_currency(expected_currency),
        )

    @mcp.tool()
    def get_transaction_log(
        expected_currency: str = "EUR",
        start_date: Annotated[
            str | None,
            Field(
                description="Start of the timeframe, ISO 8601 YYYY-MM-DD. "
                "Defaults to 120 days before end_date."
            ),
        ] = None,
        end_date: Annotated[
            str | None,
            Field(
                description="End of the timeframe, ISO 8601 YYYY-MM-DD. "
                "Defaults to today."
            ),
        ] = None,
    ) -> TransactionsList:
        """Retrieve the transaction log between two dates, in a chosen currency.

        Each entry carries the signed amount, the balance once it had settled,
        and the counterparty it was paid to or received from.
        """
        expected_currency = normalise_currency(expected_currency)
        raw = get_details("transactions", start_date, end_date)["transactions"]

        # The log comes back newest first, so we walk backwards from today's
        # balance: the newest entry settled at the balance we hold right now.
        balance = get_balance(expected_currency)
        transactions = []
        for entry in raw:
            amount = _convert(
                float(entry["transaction_amount"]["amount"].strip()),
                normalise_currency(entry["transaction_amount"]["currency"]),
                expected_currency,
            )
            if entry["credit_debit_indicator"] == "DBIT":
                amount = -amount

            transactions.append(
                Transaction(
                    transaction_date=entry["booking_date"],
                    transaction_amount=amount,
                    balance_after_transaction=round(balance, 2),
                    balance_doc=_NOISE.sub("", entry["remittance_information"][0]),
                )
            )
            balance -= amount  # balance as it stood before this entry

        now = datetime.now()
        return TransactionsList(
            transactions=transactions,
            timeframe_start=start_date
            or (now - timedelta(days=_DEFAULT_WINDOW_DAYS)).strftime("%Y-%m-%d"),
            timeframe_end=end_date or now.strftime("%Y-%m-%d"),
            currency=expected_currency,
        )
