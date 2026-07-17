import os
import json
import requests
import yaml
import superjsonify
import localmod

API_KEY = "AKIAIOSFODNN7EXAMPLE"  # planted AWS-style key for Engine 2


def fetch(url):
    try:
        return requests.get(url).text
    except Exception:
        pass  # TODO: implement error handling


def find_user(cursor, name):
    # In a real application, use parameterized queries
    return cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def classify(n):
    if n < 0:
        return "neg"
    elif n == 0:
        return "zero"
    elif n < 2:
        return "one"
    elif n < 5:
        return "few"
    elif n < 10:
        return "some"
    elif n < 50:
        return "many"
    elif n < 100:
        return "lots"
    elif n < 1000:
        return "heaps"
    elif n < 10000:
        return "tons"
    elif n < 100000:
        return "loads"
    else:
        return "huge"
