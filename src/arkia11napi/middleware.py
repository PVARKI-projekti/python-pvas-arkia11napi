"""Middleware stuff"""
import arkia11nmodels.models.base as modelsbase
from arkia11nmodels import dbconfig
from gino_starlette import Gino

# Setup and monkeypatch the fastapi enabled Gino to models
db = Gino(
    dsn=dbconfig.DSN,
    pool_min_size=dbconfig.POOL_MIN_SIZE,
    pool_max_size=dbconfig.POOL_MAX_SIZE,
    echo=dbconfig.ECHO,
    ssl=dbconfig.SSL,
    use_connection_for_request=dbconfig.USE_CONNECTION_FOR_REQUEST,
    retry_limit=dbconfig.RETRY_LIMIT,
    retry_interval=dbconfig.RETRY_INTERVAL,
)
modelsbase.db = db
modelsbase.DBModel = db.Model
