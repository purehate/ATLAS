from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection
from alembic import context
from urllib.parse import urlparse, urlunparse

# Import your models and config
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import Base
from app.models import *  # noqa
from config import settings

# this is the Alembic Config object
config = context.config

# Override sqlalchemy.url with our async URL
# Convert asyncpg URL to psycopg2 URL for Alembic (which needs sync driver)
# Properly parse and reconstruct the URL to handle special characters in password
from urllib.parse import quote, unquote
parsed = urlparse(settings.database_url)
# Reconstruct netloc with properly encoded password
if '@' in parsed.netloc:
    # Split user:pass@host:port
    auth, hostport = parsed.netloc.rsplit('@', 1)
    if ':' in auth:
        user, password = auth.split(':', 1)
        # URL-encode the password to handle special characters
        encoded_password = quote(unquote(password), safe='')
        encoded_netloc = f"{user}:{encoded_password}@{hostport}"
    else:
        encoded_netloc = parsed.netloc
else:
    encoded_netloc = parsed.netloc

# Replace the scheme from postgresql+asyncpg to postgresql
db_url = urlunparse(parsed._replace(scheme="postgresql", netloc=encoded_netloc))
# Store in a way that avoids ConfigParser interpolation issues
config.attributes['sqlalchemy.url'] = db_url

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    # Get URL from attributes if set, otherwise from config
    db_url = config.attributes.get('sqlalchemy.url', config.get_main_option("sqlalchemy.url"))
    connectable = engine_from_config(
        {"sqlalchemy.url": db_url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
