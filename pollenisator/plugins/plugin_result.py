"""
PluginResult: A declarative container for plugin parse results.

Plugins return a PluginResult instead of writing to the database directly.
The orchestrator function apply_plugin_result() processes the collected
operations in dependency order to persist them.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pollenisator.core.components.tag import Tag
from pollenisator.core.components.logger_config import logger


# ---------------------------------------------------------------------------
# Lightweight value types for deferred DB operations
# ---------------------------------------------------------------------------

@dataclass
class InfoUpdate:
    """Deferred updateInfos() call on a persisted object."""
    collection: str          # e.g. "ips", "ports"
    db_key: Dict[str, Any]   # Mongo filter to find the object (e.g. {"ip": "10.0.0.1", "port": "445", "proto": "tcp"})
    infos: Dict[str, Any]    # Dict to merge via updateInfos()


@dataclass
class TagAddition:
    """Deferred addTag() call on a persisted object."""
    collection: str          # e.g. "ips", "ports", "computers", "shares", "users"
    db_key: Dict[str, Any]   # Mongo filter to find the object
    tag: Tag


@dataclass
class UserLink:
    """Deferred Computer.add_user() / add_admin() call."""
    computer_ip: str         # IP used to find the Computer
    domain: Optional[str]
    username: Optional[str]
    password: Optional[str]
    infos: Optional[Dict[str, Any]] = None
    is_admin: bool = False


@dataclass
class FileAdd:
    """Deferred Share.add_file() call."""
    share_ip: str
    share_name: str
    path: str
    flagged: bool = False
    priv: str = ""
    size: str = ""
    domain: Optional[str] = None
    user: Optional[str] = None


@dataclass
class ObjectUpdate:
    """Deferred full-object update (updateInDb) on a persisted object."""
    collection: str
    db_key: Dict[str, Any]
    data: Dict[str, Any]     # Fields to $set


@dataclass
class ShareUpdate:
    """Deferred Share.update() for an existing share (upsert)."""
    share_ip: str
    share_name: str
    infos: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main result container
# ---------------------------------------------------------------------------

@dataclass
class PluginResult:
    """Declarative container returned by every Plugin.Parse() call.

    The first four fields preserve backward-compatibility with the old
    ``(notes, tags, lvl, targets)`` tuple contract.

    The remaining fields describe DB operations that the orchestrator will
    execute **after** the parse is complete.
    """

    # -- legacy 4-tuple fields (consumed by callers for Tool management) -----
    notes: Optional[str] = None
    tags: Optional[List[Tag]] = None
    lvl: Optional[str] = None
    targets: Optional[Dict[str, Optional[Dict[str, Optional[str]]]]] = None

    # -- objects to insert/upsert (model instances, NOT yet persisted) -------
    # Each list holds model objects created via Model(pentest).initialize(...)
    # The orchestrator will call Ip.bulk_insert / Port.bulk_insert / addInDb.
    ips: List[Any] = field(default_factory=list)
    ports: List[Any] = field(default_factory=list)
    computers: List[Any] = field(default_factory=list)
    users: List[Any] = field(default_factory=list)
    shares: List[Any] = field(default_factory=list)

    # -- deferred mutations (applied after inserts) --------------------------
    info_updates: List[InfoUpdate] = field(default_factory=list)
    tag_additions: List[TagAddition] = field(default_factory=list)
    object_updates: List[ObjectUpdate] = field(default_factory=list)
    user_links: List[UserLink] = field(default_factory=list)
    file_additions: List[FileAdd] = field(default_factory=list)
    share_updates: List[ShareUpdate] = field(default_factory=list)

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def empty() -> "PluginResult":
        """Return an all-None result (plugin rejects the file)."""
        return PluginResult()

    def is_empty(self) -> bool:
        """True when the plugin signalled it cannot parse the file."""
        return self.notes is None and self.tags is None

    def merge(self, other: "PluginResult") -> "PluginResult":
        """Merge *other* into *self* (mutates self, returns self)."""
        if other.notes is not None:
            self.notes = (self.notes or "") + "\n" + other.notes
        if other.tags:
            if self.tags is None:
                self.tags = []
            self.tags.extend(other.tags)
        if other.lvl is not None:
            self.lvl = other.lvl
        if other.targets:
            if self.targets is None:
                self.targets = {}
            self.targets.update(other.targets)
        self.ips.extend(other.ips)
        self.ports.extend(other.ports)
        self.computers.extend(other.computers)
        self.users.extend(other.users)
        self.shares.extend(other.shares)
        self.info_updates.extend(other.info_updates)
        self.tag_additions.extend(other.tag_additions)
        self.object_updates.extend(other.object_updates)
        self.user_links.extend(other.user_links)
        self.file_additions.extend(other.file_additions)
        self.share_updates.extend(other.share_updates)
        return self


# ---------------------------------------------------------------------------
# Orchestrator – applies a PluginResult to the database
# ---------------------------------------------------------------------------

def apply_plugin_result(pentest: str, result: PluginResult) -> None:
    """Persist all operations collected in *result* to the database.

    Execution order:
        1. Bulk-insert IPs  (triggers add_ip_checks, scope matching)
        2. Bulk-insert Ports (triggers add_port_checks, auto-Computer for 88/445/1433)
        3. Upsert Computers / Users / Shares  (addInDb handles existence checks)
        4. Apply InfoUpdate entries  (fetch + updateInfos)
        5. Apply TagAddition entries (fetch + addTag – preserves addTagChecks/addTagDefects)
        6. Apply ObjectUpdate entries (fetch + updateInDb)
        7. Process UserLink entries (Computer.add_user / add_admin)
        8. Process FileAdd entries  (Share.add_file)
        9. Process ShareUpdate entries (Share.update for existing shares)
    """
    if result.is_empty():
        return

    # Lazy imports to avoid circular dependencies at module load time
    from pollenisator.core.models.ip import Ip
    from pollenisator.core.models.port import Port
    from pollenisator.server.modules.activedirectory.computers import Computer
    from pollenisator.server.modules.activedirectory.users import User
    from pollenisator.server.modules.activedirectory.shares import Share

    # ---- Phase 1: Bulk-insert IPs -----------------------------------------
    if result.ips:
        Ip.bulk_insert(pentest, result.ips, look_scopes=True)

    # ---- Phase 2: Bulk-insert Ports ----------------------------------------
    if result.ports:
        Port.bulk_insert(pentest, result.ports)

    # ---- Phase 3: Upsert AD objects ----------------------------------------
    for comp in result.computers:
        comp.addInDb()

    for user in result.users:
        user.addInDb()

    for share in result.shares:
        res = share.addInDb()
        # If share already existed, update it
        if not res["res"]:
            share.update(res["iid"])

    # ---- Phase 4: Info updates ---------------------------------------------
    _COLLECTION_MODEL = {
        "ips": Ip,
        "ports": Port,
        "computers": Computer,
        "users": User,
        "shares": Share,
    }

    for upd in result.info_updates:
        model_cls = _COLLECTION_MODEL.get(upd.collection)
        if model_cls is None:
            logger.warning("apply_plugin_result: unknown collection %s", upd.collection)
            continue
        obj = model_cls.fetchObject(pentest, upd.db_key)
        if obj is not None:
            obj.updateInfos(upd.infos)
        else:
            logger.warning("apply_plugin_result: object not found for InfoUpdate %s %s", upd.collection, upd.db_key)

    # ---- Phase 5: Tag additions --------------------------------------------
    for ta in result.tag_additions:
        model_cls = _COLLECTION_MODEL.get(ta.collection)
        if model_cls is None:
            logger.warning("apply_plugin_result: unknown collection %s for TagAddition", ta.collection)
            continue
        obj = model_cls.fetchObject(pentest, ta.db_key)
        if obj is not None:
            obj.addTag(ta.tag)
        else:
            logger.warning("apply_plugin_result: object not found for TagAddition %s %s", ta.collection, ta.db_key)

    # ---- Phase 6: Full object updates --------------------------------------
    for ou in result.object_updates:
        model_cls = _COLLECTION_MODEL.get(ou.collection)
        if model_cls is None:
            continue
        obj = model_cls.fetchObject(pentest, ou.db_key)
        if obj is not None:
            for k, v in ou.data.items():
                setattr(obj, k, v)
            # AD models (Computer, User, Share) use update(); Element models use updateInDb()
            if hasattr(obj, "updateInDb"):
                obj.updateInDb()
            elif hasattr(obj, "update"):
                obj.update()
            else:
                logger.warning("apply_plugin_result: object %s has no update method", type(obj).__name__)

    # ---- Phase 7: User links -----------------------------------------------
    for ul in result.user_links:
        computer_m = Computer.fetchObject(pentest, {"ip": ul.computer_ip})
        if computer_m is None:
            logger.warning("apply_plugin_result: Computer not found for UserLink ip=%s", ul.computer_ip)
            continue
        if ul.is_admin:
            computer_m.add_admin(ul.domain, ul.username, ul.password)
        else:
            computer_m.add_user(ul.domain, ul.username, ul.password, ul.infos)

    # ---- Phase 8: File additions -------------------------------------------
    for fa in result.file_additions:
        share_m = Share.fetchObject(pentest, {"ip": fa.share_ip, "share": fa.share_name})
        if share_m is None:
            logger.warning("apply_plugin_result: Share not found for FileAdd ip=%s share=%s", fa.share_ip, fa.share_name)
            continue
        share_m.add_file(path=fa.path, flagged=fa.flagged, priv=fa.priv, size=fa.size, domain=fa.domain, user=fa.user)

    # ---- Phase 9: Share updates --------------------------------------------
    for su in result.share_updates:
        share_m = Share.fetchObject(pentest, {"ip": su.share_ip, "share": su.share_name})
        if share_m is None:
            continue
        if su.infos:
            share_m.updateInfos(su.infos)
