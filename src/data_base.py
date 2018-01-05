from sqlalchemy import (Column, Integer, String, ForeignKey, Boolean, Enum, DateTime,
                        UniqueConstraint)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm.session import Session
from enum import IntEnum


class BayesianModelMixin(object):
    """Subclasses of this class will gain some `by_*` class methods. Note, that these should
    only be used to obtain objects by unique attribute (or combination of attributes that
    make the object unique), since under the hood they use SQLAlchemy's `.one()`.

    Also note, that these class methods will raise sqlalchemy.rom.exc.NoResultFound if the object
    is not found.
    """
    def to_dict(self):
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)

        return d

    @classmethod
    def _by_attrs(cls, session, **attrs):
        try:
            return session.query(cls).filter_by(**attrs).one()
        except NoResultFound:
            raise
        except SQLAlchemyError:
            session.rollback()
            raise

    @classmethod
    def by_id(cls, session, id):
        try:
            return cls._by_attrs(session, id=id)
        except NoResultFound:
            # What to do here ?
            raise

    @classmethod
    def get_or_create(cls, session, **attrs):
        try:
            return cls._by_attrs(session, **attrs)
        except NoResultFound:
            try:
                o = cls(**attrs)
                try:
                    session.add(o)
                    session.commit()
                except SQLAlchemyError:
                    session.rollback()
                    raise
                return o
            except IntegrityError:  # object was created in the meanwhile by someone else
                return cls._by_attrs(**attrs)


Base = declarative_base(cls=BayesianModelMixin)


class EcosystemBackend(IntEnum):
    # range will increase in case of adding new backend
    # none, nodejs, java, python, ruby, go, crates
    # NOTE: when altering this, you'll manually need to create a migration that alters
    #    f8a_worker.models.Ecosystem by adding it to DB enum - see:
    #    http://stackoverflow.com/questions/14845203/altering-an-enum-field-using-alembic
    (none, npm, maven, pypi, rubygems, scm, crates, nuget) = range(8)


class Ecosystem(Base):
    __tablename__ = 'ecosystems'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True)
    url = Column(String(255))
    fetch_url = Column(String(255))
    _backend = Column(Enum(*[b.name for b in EcosystemBackend], name='ecosystem_backend_enum'))

    packages = relationship('Package', back_populates='ecosystem')

    @property
    def backend(self):
        return EcosystemBackend[self._backend]

    @backend.setter
    def backend(self, backend):
        self._backend = EcosystemBackend(backend).name

    def is_backed_by(self, backend):
        return self.backend == backend

    @classmethod
    def by_name(cls, session, name):
        try:
            return cls._by_attrs(session, name=name)
        except NoResultFound:
            # What to do here ?
            raise


class Package(Base):
    __tablename__ = 'packages'
    # ecosystem_id together with name must be unique
    __table_args__ = (UniqueConstraint('ecosystem_id', 'name', name='ep_unique'),)

    id = Column(Integer, primary_key=True)
    ecosystem_id = Column(Integer, ForeignKey(Ecosystem.id))
    name = Column(String(255), index=True)

    ecosystem = relationship(Ecosystem, back_populates='packages', lazy='joined')
    versions = relationship('Version', back_populates='package')

    @classmethod
    def by_name(cls, session, name):
        # TODO: this is dangerous at is does not consider Ecosystem
        try:
            return cls._by_attrs(session, name=name)
        except NoResultFound:
            # What to do here ?
            raise


class Version(Base):
    __tablename__ = 'versions'
    # package_id together with version identifier must be unique
    __table_args__ = (UniqueConstraint('package_id', 'identifier', name='pv_unique'),)

    id = Column(Integer, primary_key=True)
    package_id = Column(Integer, ForeignKey(Package.id))
    identifier = Column(String(255), index=True)

    package = relationship(Package, back_populates='versions', lazy='joined')
    analyses = relationship('Analysis', back_populates='version')

    @classmethod
    def by_identifier(cls, session, identifier):
        try:
            return cls._by_attrs(session, identifier=identifier)
        except NoResultFound:
            # What to do here ?
            raise


class Analysis(Base):
    __tablename__ = 'analyses'

    id = Column(Integer, primary_key=True)
    version_id = Column(Integer, ForeignKey(Version.id), index=True)
    access_count = Column(Integer, default=0)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    # debugging and stuff
    subtasks = Column(JSONB)
    release = Column(String(255))  # TODO: is length 255 enough for release?
    audit = Column(JSONB)

    version = relationship(Version, back_populates='analyses', lazy='joined')

    @property
    def analyses(self):
        s = Session.object_session(self)
        if s:
            worker_results = s.query(WorkerResult).filter(WorkerResult.analysis_id == self.id)
            return {wr.worker: wr.task_result for wr in worker_results}
        return {}

    @property
    def raw_analyses(self):
        s = Session.object_session(self)
        if s:
            return s.query(WorkerResult).filter(WorkerResult.analysis_id == self.id)
        return []


class WorkerResult(Base):
    __tablename__ = 'worker_results'

    id = Column(Integer, primary_key=True)
    worker = Column(String(255), index=True)
    worker_id = Column(String(64), unique=True)
    # `external_request_id` provides mapping of particular `worker_result`
    # to externally defined identifier, when `external_request_id` is provided
    # the value of `analysis_id` should be `NULL`
    external_request_id = Column(String(64), index=True)
    analysis_id = Column(ForeignKey(Analysis.id), index=True)
    task_result = Column(JSONB)
    error = Column(Boolean, nullable=False, default=False)

    analysis = relationship(Analysis)

    @property
    def ecosystem(self):
        return self.analysis.version.package.ecosystem

    @property
    def package(self):
        return self.analysis.version.package

    @property
    def version(self):
        return self.analysis.version
