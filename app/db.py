from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(db_url: str):
    # Special handling for in-memory SQLite so it persists across sessions in tests
    if db_url.startswith("sqlite") and ":memory:" in db_url:
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

    if db_url.startswith("sqlite"):
        return create_engine(db_url, connect_args={"check_same_thread": False})

    return create_engine(db_url)


def make_sessionmaker(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)