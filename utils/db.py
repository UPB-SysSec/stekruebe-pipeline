from neo4j import GraphDatabase as _neo4j_GraphDatabase
from pymongo import MongoClient as _MongoClient
from pymongo.database import Database as _MongoDatabase
from pymongo.collection import Collection as _MongoCollection
from abc import ABC, abstractmethod
import functools
import os
import logging
import atexit
from . import credentials

# process local singletons for MongoDB and Neo4j


class _ProcessLocal(ABC):
    def __init__(self, *args, **kwargs) -> None:
        self.__instance_INTERNAL = None
        self.__init_args = args
        self.__init_kwargs = kwargs
        self.__pid = None
        pass

    @property
    def _is_same_pid(self):
        return os.getpid() == self.__pid

    @property
    def _instance(self):
        if self.__instance_INTERNAL is None or not self._is_same_pid:
            self.__pid = os.getpid()
            logging.debug(f"Creating new instance (Class: {self.__class__.__name__})")
            self.__instance_INTERNAL = self._create_instance(*self.__init_args, **self.__init_kwargs)
        return self.__instance_INTERNAL

    @property
    def _was_initialized(self):
        return self.__instance_INTERNAL is not None

    @abstractmethod
    def _create_instance(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        return getattr(self._instance, name)


class Neo4j(_ProcessLocal):
    def _create_instance(self, *args, **kwargs):
        atexit.register(self.__close)
        return _neo4j_GraphDatabase.driver(*args, **kwargs)

    def __close(self):
        if self._was_initialized:
            self._instance.close()


# functools.update_wrapper(Neo4j, _neo4j_GraphDatabase.driver)


class MongoCollection(_ProcessLocal):

    def _create_instance(self, database, collection_name):
        return database._instance[collection_name]


# functools.update_wrapper(MongoCollection, _MongoCollection)


class MongoDatabase(_ProcessLocal):

    def _create_instance(self, mogodb, database_name):
        return mogodb._instance[database_name]

    def __getitem__(self, key) -> _MongoCollection:
        return MongoCollection(database=self, collection_name=key)


# functools.update_wrapper(MongoDatabase, _MongoDatabase)


class MongoDB(_ProcessLocal):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def _create_instance(self, *args, **kwargs):
        return _MongoClient(*args, **kwargs)

    def __getitem__(self, key) -> _MongoDatabase:
        return MongoDatabase(database_name=key, mogodb=self)


# functools.update_wrapper(MongoDB, _MongoClient)


def connect_mongo(creds=..., url=..., verify_connectivity=True) -> _MongoClient:
    if url is not ... and creds is not ...:
        raise ValueError("Cannot use creds and url at the same time")

    if creds is ...:
        creds = credentials.mongodb_creds
    if url is ...:
        url = f"mongodb://{creds.as_str()}@127.0.0.1:27017/?authSource=admin&readPreference=primary&directConnection=true&ssl=true"

    mongo_driver = MongoDB(url, tlsAllowInvalidCertificates=True)
    if verify_connectivity:
        mongo_driver.server_info()
    return mongo_driver


def connect_neo4j(creds=..., verify_connectivity=True) -> _neo4j_GraphDatabase:
    if creds is ...:
        creds = credentials.neo4j_creds
    neo4j_driver = Neo4j("bolt://localhost:7687", auth=creds.as_tuple())
    if verify_connectivity:
        neo4j_driver.verify_connectivity()
    return neo4j_driver
