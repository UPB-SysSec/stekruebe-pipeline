from flask import Flask
from pathlib import Path
from pymongo import MongoClient
from bson import ObjectId
import importlib.util
import sys


def import_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


import_from_path("utils", Path(__file__).parent.parent / "utils" / "__init__.py")

import utils.db


mongo_collection = utils.db.connect_mongo()["steckruebe"]["ticket_redirection_2024-08-19_19:28"]


app = Flask(__name__)


@app.route("/<doc_id>")
def hello(doc_id):
    try:
        doc_id = bytes.fromhex(doc_id)
    except ValueError:
        return "Invalid ID (non hex)", 400
    res = mongo_collection.find_one({"_id": ObjectId(doc_id)})
    del res["_id"]
    return res


if __name__ == "__main__":
    app.run(host="172.17.0.1")
